"""
prevention-engine/level1.py
Main Prevention Engine — Flask API on port 5002.

Start with:  sudo python3 prevention-engine/level1.py
"""

import os
import sys
import json
import time
import subprocess
import threading
import logging
import requests
import yaml
import atexit
from datetime import datetime
from typing import Optional
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(__file__))
import db
from components import get_all_components, pick_component, _discover_ip, VICTIM_MAC
from network_topology import topology
from level2_components import get_l2_components, should_apply_l2
from level3_components import get_l3_components, should_apply_l3
# Level 4 removed — system uses 3 defense levels only
import honeypot
import forensics

# ── Load config ──
_CFG_PATH = os.path.join(os.path.dirname(__file__), "config.yml")

def _load_config():
    try:
        with open(_CFG_PATH) as f:
            return yaml.safe_load(f)
    except Exception:
        return {}

_cfg = _load_config()
BACKEND_URL    = _cfg.get("backend", {}).get("url", "http://localhost:8080")
DETECTION_EP   = _cfg.get("backend", {}).get("detection_endpoint", "/api/detection/events/recent")
PORT           = _cfg.get("engine", {}).get("port", 5002)
POLL_INTERVAL  = _cfg.get("engine", {}).get("poll_interval", 3)
PING_COUNT     = _cfg.get("engine", {}).get("ping_count", 3)
MIN_CONF_L1 = _cfg.get("thresholds", {}).get("level1", 40)
MIN_CONF_L2 = _cfg.get("thresholds", {}).get("level2", 60)
MIN_CONF_L3 = _cfg.get("thresholds", {}).get("level3", 85)
# L4 removed — 3-level system
VICTIM_IP   = os.getenv("VICTIM_IP", "")  # Set via env if known; empty = auto-discover gateway
GATEWAY_IP  = None  # Initialized at startup after function defs

# ── Logging ──
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
engine_logger = logging.getLogger("engine")
engine_logger.setLevel(logging.DEBUG)
if not engine_logger.handlers:
    fh = logging.FileHandler(os.path.join(LOG_DIR, "engine.log"))
    fh.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
    engine_logger.addHandler(fh)

# ── Flask app ──
app = Flask(__name__)
CORS(app)

# ── In-memory response cache (avoids repeated DB hits) ──
_cache = {}
_CACHE_TTL = 3  # seconds

def _cached(key, fetcher):
    """Return cached result if < TTL seconds old, else refresh."""
    now = time.time()
    if key in _cache and (now - _cache[key]["ts"]) < _CACHE_TTL:
        return _cache[key]["data"]
    data = fetcher()
    _cache[key] = {"data": data, "ts": now}
    return data

def _invalidate_cache():
    _cache.clear()

# ── L3 alert notification cooldown ──
_last_l3_alert_time = 0
_L3_ALERT_COOLDOWN = 300  # 5 minutes

STATE = {
    "session_id": None, "running": False, "events_processed": 0,
    "seen_ids": set(), "last_poll": None, "active_components": [],
}

# ── Ping measurement ──
def _ping_ms(ip: str) -> Optional[float]:
    if not ip: return None
    try:
        result = subprocess.run(["ping", "-c", str(PING_COUNT), "-W", "1", ip],
                                capture_output=True, text=True, timeout=10)
        for line in result.stdout.splitlines():
            if "rtt" in line and "/" in line:
                return float(line.split("=")[1].strip().split("/")[1])
    except Exception:
        pass
    return None

def _get_gateway_ip() -> Optional[str]:
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, timeout=4).stdout
        words = out.split()
        if "via" in words: return words[words.index("via") + 1]
    except Exception:
        pass
    return None

def _measure_reconnect(victim_mac: str) -> Optional[float]:
    if VICTIM_IP: return _ping_ms(VICTIM_IP)
    ip = _discover_ip(victim_mac)
    if ip: return _ping_ms(ip)
    if GATEWAY_IP: return _ping_ms(GATEWAY_IP)
    return None

# ── Fetch detections ──
def _fetch_detections():
    try:
        r = requests.get(f"{BACKEND_URL}{DETECTION_EP}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            return data if isinstance(data, list) else data.get("data", [])
    except Exception:
        pass
    return []

# ── Event processing ──
_VICTIM_MAC_FALLBACK = os.getenv("VICTIM_MAC", "4C:6F:9C:F4:FA:63").lower()
_AP_MAC_FALLBACK     = os.getenv("AP_MAC",     "9E:A8:2C:C2:1F:D9").lower()

def _event_involves_registered_network(attacker: str, target: str) -> bool:
    if topology.protected_bssids or topology.protected_clients:
        return topology.event_is_relevant(attacker, target)
    a, t = (attacker or "").lower(), (target or "").lower()
    return _VICTIM_MAC_FALLBACK in (a, t) or _AP_MAC_FALLBACK in (a, t)

def _process_event(event: dict):
    raw_conf = event.get("confidence") or event.get("mlConfidence") or 0
    confidence = float(raw_conf) * 100 if float(raw_conf) <= 1.0 else float(raw_conf)
    total_score = float(event.get("totalScore") or 0)
    confidence = max(confidence, total_score)
    attacker_mac = event.get("attackerMac") or event.get("srcMac") or "UNKNOWN"
    victim_mac = event.get("targetMac") or event.get("victimMac") or VICTIM_MAC
    if confidence < MIN_CONF_L1: return
    if not _event_involves_registered_network(attacker_mac, victim_mac): return
    victim_clients = topology.get_victim_clients(attacker_mac, victim_mac)
    victim_mac = victim_clients[0] if victim_clients else _VICTIM_MAC_FALLBACK
    det_id = event.get("eventId") or event.get("id") or "unknown"
    engine_logger.info(f"Processing event {det_id}: confidence={confidence:.1f}%")
    print(f"\n[ENGINE] Confidence={confidence:.1f}% | Attacker: {attacker_mac} | Victim: {victim_mac}")

    baseline_ms = _measure_reconnect(victim_mac)
    print(f"  Baseline: {baseline_ms} ms")
    fired_components = []
    level1_fired = level2_fired = level3_fired = False
    level4_fired = False  # Always false — L4 removed
    all_ok = True

    if confidence >= MIN_CONF_L1:
        level1_fired = True
        for comp in get_all_components():
            r = comp.apply({"attacker_mac": attacker_mac, "victim_mac": victim_mac, "confidence": confidence})
            fired_components.append(comp.id)
            if not r.get("ok"): all_ok = False
            print(f"    [{comp.id}] {comp.label}: {r.get('detail','')[:60]}")
    if confidence >= MIN_CONF_L2:
        level2_fired = True
        for comp in get_l2_components():
            r = comp.apply({"attacker_mac": attacker_mac, "victim_mac": victim_mac, "confidence": confidence})
            fired_components.append(comp.id)
            if not r.get("ok"): all_ok = False
            print(f"    [{comp.id}] {comp.label}: {r.get('detail','')[:60]}")
    if confidence >= MIN_CONF_L3:
        level3_fired = True
        for comp in get_l3_components():
            r = comp.apply({"attacker_mac": attacker_mac, "victim_mac": victim_mac, "confidence": confidence})
            fired_components.append(comp.id)
            if not r.get("ok"): all_ok = False
            print(f"    [{comp.id}] {comp.label}: {r.get('detail','')[:60]}")

        # ── Trigger email/SMS alerts at L3 (with cooldown) ──
        global _last_l3_alert_time
        now = time.time()
        if (now - _last_l3_alert_time) >= _L3_ALERT_COOLDOWN:
            _last_l3_alert_time = now
            try:
                alert_payload = {
                    "type": "DEAUTH_ATTACK", "severity": "CRITICAL",
                    "attackerMac": attacker_mac, "targetMac": victim_mac,
                    "targetBssid": topology.ssid_for_bssid(_AP_MAC_FALLBACK) or "supreeth",
                    "channel": topology.channel_for_bssid(_AP_MAC_FALLBACK) or 11,
                    "mlConfidence": confidence / 100.0,
                    "score": confidence,
                    "timestamp": datetime.now().isoformat(),
                }
                resp = requests.post(f"{BACKEND_URL}/api/detection/alerts", json=alert_payload, timeout=5)
                engine_logger.info(f"L3 alert sent to backend: status={resp.status_code}")
                print(f"  📧 L3 Alert notification sent (email+SMS)")
            except Exception as e:
                engine_logger.error(f"L3 alert notification failed: {e}")
        else:
            remaining = int(_L3_ALERT_COOLDOWN - (now - _last_l3_alert_time))
            print(f"  ⏳ L3 Alert cooldown ({remaining}s remaining)")
    # Level 4 removed — 3-level defense system
    time.sleep(1.0)
    optimized_ms = _measure_reconnect(victim_mac)
    print(f"  Optimised: {optimized_ms} ms")
    improvement_pct = None
    if baseline_ms and optimized_ms and baseline_ms > 0:
        improvement_pct = round(((baseline_ms - optimized_ms) / baseline_ms) * 100, 1)

    # Forensics (async)
    forensic_path = None
    try:
        event_data = {
            "event_id": det_id, "timestamp": datetime.now().isoformat(),
            "confidence": confidence, "attacker_mac": attacker_mac, "victim_mac": victim_mac,
            "ssid": topology.ssid_for_bssid(_AP_MAC_FALLBACK) or "supreeth",
            "channel": topology.channel_for_bssid(_AP_MAC_FALLBACK) or 11,
            "level1_fired": level1_fired, "level2_fired": level2_fired,
            "level3_fired": level3_fired, "level4_fired": level4_fired,
            "honeypot_active": honeypot.get_status().get("active", False),
            "baseline_ms": baseline_ms, "optimized_ms": optimized_ms,
            "improvement_pct": improvement_pct,
        }
        def _run_forensics():
            try:
                result = forensics.collect_evidence(event_data)
                engine_logger.info(f"Forensic evidence collected: {result.get('report_file')}")
            except Exception as e:
                engine_logger.error(f"Forensic collection failed: {e}")
        threading.Thread(target=_run_forensics, daemon=True).start()
    except Exception as e:
        engine_logger.warning(f"Forensics setup failed: {e}")

    status = "measured" if (baseline_ms is not None and optimized_ms is not None) else ("applied" if all_ok else "error")
    try:
        db.insert_event(
            session_id=STATE["session_id"], detection_event_id=det_id,
            attacker_mac=attacker_mac, victim_mac=victim_mac, confidence=confidence,
            baseline_ms=baseline_ms, optimized_ms=optimized_ms, improvement_pct=improvement_pct,
            level1_fired=level1_fired, level2_fired=level2_fired,
            level3_fired=level3_fired, level4_fired=level4_fired,
            components_fired=",".join(fired_components),
            honeypot_active=honeypot.get_status().get("active", False),
            forensic_report_path=forensic_path, status=status,
        )
        STATE["events_processed"] += 1
        STATE["active_components"] = fired_components
        print(f"  ✅ DB saved. Components: {','.join(fired_components)}. Improvement: {improvement_pct}%")
    except Exception as e:
        print(f"  ❌ DB insert failed: {e}")
        engine_logger.error(f"DB insert failed: {e}")

# ── Poll loop ──
def _poll_loop():
    engine_logger.info(f"Poll loop started: {BACKEND_URL}{DETECTION_EP} every {POLL_INTERVAL}s")
    while STATE["running"]:
        try:
            detections = _fetch_detections()
            STATE["last_poll"] = datetime.now().isoformat()
            for det in detections:
                det_id = det.get("eventId") or det.get("id")
                if det_id and det_id in STATE["seen_ids"]: continue
                # Check if event has sufficient confidence BEFORE marking as seen.
                # Events with low initial scores (before ML update) should NOT be
                # permanently skipped — they may be retried when ML updates totalScore.
                raw_conf = det.get("confidence") or det.get("mlConfidence") or 0
                confidence = float(raw_conf) * 100 if float(raw_conf) <= 1.0 else float(raw_conf)
                total_score = float(det.get("totalScore") or 0)
                effective_conf = max(confidence, total_score)
                if effective_conf < MIN_CONF_L1:
                    # Don't add to seen_ids — ML may update this event later
                    continue
                if det_id: STATE["seen_ids"].add(det_id)
                _process_event(det)
        except Exception as e:
            engine_logger.error(f"Poll error: {e}")
        time.sleep(POLL_INTERVAL)

# ── REST API ──
@app.route("/prevention/health", methods=["GET"])
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "running": STATE["running"], "session_id": STATE["session_id"],
                    "events_processed": STATE["events_processed"], "last_poll": STATE["last_poll"],
                    "active_components": STATE["active_components"]})

@app.route("/prevention/status", methods=["GET"])
@app.route("/stats", methods=["GET"])
def status():
    try: stats = db.get_stats()
    except Exception as e: stats = {"error": str(e)}
    return jsonify({"engine": "running" if STATE["running"] else "stopped", "session_id": STATE["session_id"], **stats})

@app.route("/prevention/events", methods=["GET"])
def events():
    limit = int(request.args.get("limit", 50))
    try: return jsonify(_cached(f"events_{limit}", lambda: db.get_events(limit)))
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/prevention/stats", methods=["GET"])
def stats():
    try: return jsonify(_cached("stats", db.get_stats))
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/prevention/events", methods=["DELETE"])
def clear_all_events():
    try:
        db.clear_events()
        _invalidate_cache()
        STATE["events_processed"] = 0
        # DO NOT clear STATE["seen_ids"] here, otherwise the polling loop will
        # re-fetch and re-process recent events from the Java backend immediately!
        
        try: STATE["session_id"] = db.start_session()
        except Exception: pass
        
        # Clear forensic reports and pcaps
        import glob
        import forensics
        for f in glob.glob(os.path.join(forensics.CAPTURE_DIR, "*.pcap")):
            try: os.remove(f)
            except Exception as e: print(f"Failed to delete {f}: {e}")
        for f in glob.glob(os.path.join(forensics.REPORT_DIR, "*.pdf")):
            try: os.remove(f)
            except Exception as e: print(f"Failed to delete {f}: {e}")
                
        return jsonify({"cleared": True})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/prevention/apply", methods=["POST"])
@app.route("/trigger-level/<int:level>", methods=["POST"])
def manual_apply(level=None):
    data = request.json or {}
    confidence = float(data.get("confidence", 50))
    attacker_mac = data.get("attacker_mac", "AA:BB:CC:DD:EE:FF")
    victim_mac = data.get("victim_mac", VICTIM_MAC)
    if level:
        level_map = {1: 45, 2: 65, 3: 90, 4: 97}
        confidence = level_map.get(level, 50)
    det = {"confidence": confidence / 100, "attackerMac": attacker_mac,
           "targetMac": victim_mac, "eventId": f"manual-{int(time.time())}"}
    threading.Thread(target=_process_event, args=(det,), daemon=True).start()
    return jsonify({"queued": True, "confidence": confidence})

@app.route("/honeypot/start", methods=["POST"])
def honeypot_start():
    return jsonify(honeypot.start())

@app.route("/honeypot/stop", methods=["POST"])
def honeypot_stop():
    return jsonify(honeypot.stop())

@app.route("/honeypot/status", methods=["GET"])
def honeypot_status():
    return jsonify(honeypot.get_status())

@app.route("/forensics/reports", methods=["GET"])
def forensics_reports():
    return jsonify(forensics.list_reports())

@app.route("/forensics/download/<path:filename>", methods=["GET"])
def forensics_download(filename):
    filename = os.path.basename(filename)
    report_path = os.path.join(forensics.REPORT_DIR, filename)
    if os.path.isfile(report_path): return send_file(report_path, as_attachment=True)
    pcap_path = os.path.join(forensics.CAPTURE_DIR, filename)
    if os.path.isfile(pcap_path): return send_file(pcap_path, as_attachment=True)
    return jsonify({"error": "File not found"}), 404

@app.route("/forensics/generate/<event_id>", methods=["POST"])
def forensics_generate(event_id):
    event_data = {
        "event_id": event_id, "timestamp": datetime.now().isoformat(),
        "confidence": float(request.json.get("confidence", 50)) if request.json else 50,
        "attacker_mac": request.json.get("attacker_mac", "UNKNOWN") if request.json else "UNKNOWN",
        "victim_mac": request.json.get("victim_mac", "UNKNOWN") if request.json else "UNKNOWN",
        "ssid": "supreeth", "channel": 11,
        "level1_fired": True, "level2_fired": False, "level3_fired": False, "level4_fired": False,
        "honeypot_active": honeypot.get_status().get("active", False),
        "baseline_ms": None, "optimized_ms": None, "improvement_pct": None,
    }
    return jsonify(forensics.collect_evidence(event_data))

# ── Startup / Shutdown ──
def _startup():
    print("=" * 56)
    print("  🛡  Prevention Engine v3.0")
    print(f"  ├─ API port:    {PORT}")
    print(f"  ├─ Thresholds:  L1≥{MIN_CONF_L1}% L2≥{MIN_CONF_L2}% L3≥{MIN_CONF_L3}%")
    print(f"  ├─ Backend:     {BACKEND_URL}")
    print(f"  └─ DB:          Aiven MySQL / wifi_deauth")
    print("=" * 56)
    global GATEWAY_IP
    GATEWAY_IP = _get_gateway_ip()
    topology.start_background_refresh()
    try: db.init_schema()
    except Exception as e: print(f"⚠️  DB schema init failed: {e}")
    try:
        STATE["session_id"] = db.start_session()
        print(f"  Session ID: {STATE['session_id']}")
    except Exception as e: print(f"⚠️  Could not create session: {e}")
    STATE["running"] = True
    threading.Thread(target=_poll_loop, daemon=True).start()

def _shutdown():
    STATE["running"] = False
    if honeypot.get_status().get("active"): honeypot.stop()
    if STATE["session_id"]:
        try: db.end_session(STATE["session_id"])
        except Exception: pass

atexit.register(_shutdown)

if __name__ == "__main__":
    _startup()
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
