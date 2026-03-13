"""
Wi-Fi Shield — 3-Layer Detection Engine (Single File)
=====================================================
Sections:
  A - Shared State
  B - Layer 1: Rate Analyzer
  C - Layer 2: ML Ensemble
  D - Layer 3: Physical Validator
  E - Final Score Combiner
  F - Event Manager (process_packet)
  G - Sniffer
  H - Status Reset Background Task
  I - Prevention Bridge
"""

import os
import time
import asyncio
import logging
import threading
import joblib
import numpy as np
from datetime import datetime, timedelta
from scapy.all import AsyncSniffer, Dot11, Dot11Deauth, RadioTap
import mysql.connector
import requests

# ── Logging ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-15s | %(levelname)-5s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("DetectionEngine")

# ═══════════════════════════════════════════════════════════
# SECTION A — SHARED STATE
# ═══════════════════════════════════════════════════════════

REGISTERED_BSSIDS: set = set()  # loaded from DB on startup, all lowercase

rate_tracker: dict = {}     # { src_mac: [datetime, datetime, ...] }
open_bursts: dict = {}      # { src_mac: { event_id, created_at } }

BURST_WINDOW_SECONDS = 30
INTERFACE = os.environ.get("WIFI_INTERFACE", "wlan1")
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8080")
PREVENTION_URL = os.environ.get("PREVENTION_URL", "http://localhost:5002")

# Database connection config
DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "mysql-2a681751-supreethvennila69-f64d.e.aivencloud.com"),
    "port": int(os.environ.get("DB_PORT", "23766")),
    "user": os.environ.get("DB_USER", "avnadmin"),
    "password": os.environ.get("DB_PASSWORD", "<YOUR_DB_PASSWORD>"),
    "database": os.environ.get("DB_NAME", "wifi_deauth"),
    "ssl_disabled": False,
}

# ML Models (loaded on startup)
models = {}
scaler = None

# WebSocket clients
ws_clients: set = set()

# Sniffer reference
_sniffer = None
_sniffer_packet_count = 0


# ═══════════════════════════════════════════════════════════
# DATABASE HELPERS
# ═══════════════════════════════════════════════════════════

def get_db():
    """Get a fresh database connection."""
    conn = mysql.connector.connect(**DB_CONFIG)
    return conn


def db_execute(sql, params=None, fetch=False):
    """Execute SQL and optionally fetch results."""
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute(sql, params or ())
        if fetch:
            result = cur.fetchall()
            return result
        conn.commit()
        return cur.lastrowid
    finally:
        cur.close()
        conn.close()


# ═══════════════════════════════════════════════════════════
# SECTION B — LAYER 1: RATE ANALYZER
# ═══════════════════════════════════════════════════════════

def calculate_rate_score(src_mac: str) -> float:
    """Rate-based scoring: how many packets from this MAC in last 10 seconds."""
    now = datetime.utcnow()

    if src_mac not in rate_tracker:
        rate_tracker[src_mac] = []

    rate_tracker[src_mac].append(now)

    # Remove entries older than 10 seconds
    rate_tracker[src_mac] = [
        t for t in rate_tracker[src_mac]
        if (now - t).total_seconds() <= 10
    ]

    count = len(rate_tracker[src_mac])

    if count <= 3:
        return 0.0
    if count <= 8:
        return 40.0
    if count <= 20:
        return 70.0
    return 100.0


# ═══════════════════════════════════════════════════════════
# SECTION C — LAYER 2: ML ENSEMBLE
# ═══════════════════════════════════════════════════════════

def calculate_ml_score(rate_score: float, rssi) -> tuple:
    """
    Run all 4 ML models and return (ml_score, agreement).
    ml_score: 0-100 float
    agreement: 0-4 int (how many models predicted attack)
    """
    if not models:
        logger.warning("No ML models loaded, returning fallback scores")
        return (rate_score * 0.8, 0)

    # Build feature vector
    if rssi is None:
        rssi_norm = 0.5
    else:
        rssi_val = float(rssi)
        rssi_norm = max(0.0, min(1.0, (-30.0 - rssi_val) / (-30.0 - (-90.0))))

    features = np.array([[rate_score / 100.0, rssi_norm]])

    # Scale features if scaler available
    if scaler is not None:
        try:
            features = scaler.transform(features)
        except Exception:
            pass  # Use raw features if scaler fails

    probs = []
    for name, model in models.items():
        try:
            prob = model.predict_proba(features)[0][1]
            probs.append(prob)
        except Exception as e:
            logger.warning("Model %s failed: %s", name, e)
            probs.append(0.5)

    if not probs:
        return (rate_score * 0.8, 0)

    ml_score = (sum(probs) / len(probs)) * 100.0
    agreement = sum(1 for p in probs if p > 0.5)

    return (ml_score, agreement)


# ═══════════════════════════════════════════════════════════
# SECTION D — LAYER 3: PHYSICAL VALIDATOR
# ═══════════════════════════════════════════════════════════

def calculate_physical_score(rssi, dst_mac: str) -> float:
    """Physical-layer validation based on RSSI and broadcast behavior."""
    # RSSI score
    if rssi is None:
        rssi_score = 60.0
    else:
        rssi_val = float(rssi)
        if rssi_val > -30:
            rssi_score = 100.0
        elif rssi_val > -50:
            rssi_score = 70.0
        elif rssi_val > -70:
            rssi_score = 40.0
        elif rssi_val > -85:
            rssi_score = 20.0
        else:
            rssi_score = 0.0

    # Broadcast bonus
    bonus = 20.0 if dst_mac == "ff:ff:ff:ff:ff:ff" else 0.0

    return min(rssi_score + bonus, 100.0)


# ═══════════════════════════════════════════════════════════
# SECTION E — FINAL SCORE COMBINER
# ═══════════════════════════════════════════════════════════

def combine_scores(rate: float, ml: float, physical: float) -> float:
    """Weighted combination: Rate 40%, ML 40%, Physical 20%."""
    return (rate * 0.40) + (ml * 0.40) + (physical * 0.20)


def get_verdict(final_score: float) -> str:
    """Map final score to verdict string."""
    if final_score < 30:
        return "NORMAL"
    elif final_score < 50:
        return "SUSPICIOUS"
    elif final_score < 75:
        return "ATTACK"
    else:
        return "CRITICAL"


# ═══════════════════════════════════════════════════════════
# SECTION F — EVENT MANAGER
# ═══════════════════════════════════════════════════════════

def process_packet(packet_dict: dict):
    """
    Process a single deauth packet through the 3-layer pipeline.
    Creates or updates events in the database.
    """
    # Step 1: Normalize MACs
    src_mac = packet_dict["src_mac"].lower()
    dst_mac = packet_dict["dst_mac"].lower()
    bssid = packet_dict["bssid"].lower()
    rssi = packet_dict.get("rssi")
    captured_at = packet_dict.get("captured_at", datetime.utcnow().isoformat() + "Z")

    # Step 2: Calculate all 3 layers
    rate_score = calculate_rate_score(src_mac)
    ml_score, agr = calculate_ml_score(rate_score, rssi)
    phys_score = calculate_physical_score(rssi, dst_mac)
    final_score = combine_scores(rate_score, ml_score, phys_score)
    verdict = get_verdict(final_score)

    # Step 3: Update total_packets counter ALWAYS
    try:
        db_execute(
            "UPDATE system_stats SET total_packets = total_packets + 1 WHERE id = 1"
        )
    except Exception as e:
        logger.error("Failed to update total_packets: %s", e)

    # Step 4: Discard NORMAL verdict
    if verdict == "NORMAL":
        return

    # Step 5: Check for open burst (grouping)
    now = datetime.utcnow()

    if src_mac in open_bursts:
        burst = open_bursts[src_mac]
        diff = (now - burst["created_at"]).total_seconds()

        if diff <= BURST_WINDOW_SECONDS:
            # SAME BURST: update existing event
            event_id = burst["event_id"]
            try:
                db_execute(
                    """UPDATE deauth_events SET
                       packet_count = packet_count + 1,
                       last_seen = %s,
                       final_score = GREATEST(final_score, %s)
                    WHERE id = %s""",
                    (captured_at, final_score, event_id),
                )
            except Exception as e:
                logger.error("Failed to update burst event %s: %s", event_id, e)

            logger.info("[BURST] updated event #%s", event_id)

            # Broadcast update
            _broadcast_ws({
                "type": "update_event",
                "id": event_id,
                "packet_count": _get_event_packet_count(event_id),
                "final_score": final_score,
            })
            return  # do NOT create new event

    # Step 6: Create new event
    try:
        new_id = db_execute(
            """INSERT INTO deauth_events
               (src_mac, dst_mac, bssid, rssi, first_seen, last_seen,
                packet_count, rate_score, ml_score, physical_score,
                final_score, verdict, ml_agreement, resolved)
            VALUES (%s, %s, %s, %s, %s, %s, 1, %s, %s, %s, %s, %s, %s, 0)""",
            (src_mac, dst_mac, bssid, rssi, captured_at, captured_at,
             rate_score, ml_score, phys_score, final_score, verdict, agr),
        )
    except Exception as e:
        logger.error("Failed to create deauth event: %s", e)
        return

    # Store in open_bursts
    open_bursts[src_mac] = {
        "event_id": new_id,
        "created_at": now,
    }

    # Update system_stats counters
    try:
        updates = ["total_events = total_events + 1"]
        if verdict == "SUSPICIOUS":
            updates.append("suspicious_events = suspicious_events + 1")
        elif verdict == "ATTACK":
            updates.append("attack_events = attack_events + 1")
        elif verdict == "CRITICAL":
            updates.append("critical_events = critical_events + 1")

        if verdict in ("ATTACK", "CRITICAL"):
            updates.append("current_status = 'UNSAFE'")

        db_execute(
            f"UPDATE system_stats SET {', '.join(updates)} WHERE id = 1"
        )
    except Exception as e:
        logger.error("Failed to update system_stats: %s", e)

    logger.info(
        "[NEW EVENT] #%s src=%s verdict=%s score=%.1f rate=%.0f ml=%.0f physical=%.0f",
        new_id, src_mac, verdict, final_score, rate_score, ml_score, phys_score,
    )

    # Fetch full event for broadcast
    event_data = _get_event_by_id(new_id)
    if event_data:
        _broadcast_ws({"type": "new_event", "event": event_data})

    # Trigger email alert (async, non-blocking)
    threading.Thread(target=_send_email_alert, args=(event_data,), daemon=True).start()

    # Trigger prevention engine (async, non-blocking)
    threading.Thread(
        target=trigger_prevention,
        args=(verdict, ml_score, final_score, src_mac, bssid),
        daemon=True,
    ).start()


def _get_event_packet_count(event_id) -> int:
    """Get current packet count for an event."""
    try:
        rows = db_execute(
            "SELECT packet_count FROM deauth_events WHERE id = %s",
            (event_id,), fetch=True,
        )
        return rows[0]["packet_count"] if rows else 0
    except Exception:
        return 0


def _get_event_by_id(event_id) -> dict:
    """Fetch a single event by ID."""
    try:
        rows = db_execute(
            "SELECT * FROM deauth_events WHERE id = %s",
            (event_id,), fetch=True,
        )
        return rows[0] if rows else None
    except Exception:
        return None


def _send_email_alert(event_data):
    """Send email alert via Java backend."""
    if not event_data:
        return
    try:
        requests.post(
            f"{BACKEND_URL}/api/detection/alert",
            json={
                "type": "DEAUTH_FLOOD",
                "severity": event_data.get("verdict", "ATTACK"),
                "attackerMac": event_data.get("src_mac", ""),
                "targetMac": event_data.get("dst_mac", ""),
                "targetBssid": event_data.get("bssid", ""),
                "score": event_data.get("final_score", 0),
                "message": f"Attack detected: {event_data.get('verdict')} (Score: {event_data.get('final_score', 0):.1f})",
            },
            timeout=3,
        )
    except Exception as e:
        logger.warning("Email alert failed: %s", e)


# ═══════════════════════════════════════════════════════════
# SECTION G — SNIFFER
# ═══════════════════════════════════════════════════════════

_sniffer_running = False  # flag for restart loop

def start_sniffer():
    """Start the packet sniffer with auto-restart on failure."""
    global _sniffer, _sniffer_packet_count, _sniffer_running

    # Load registered BSSIDs from database
    load_registered_bssids()

    logger.info("[SNIFFER] Loaded BSSIDs: %s", REGISTERED_BSSIDS)

    if not REGISTERED_BSSIDS:
        logger.warning("[SNIFFER] No registered BSSIDs found! Will not capture anything.")

    def packet_handler(pkt):
        global _sniffer_packet_count
        try:
            if not pkt.haslayer(Dot11):
                return
            dot11 = pkt.getlayer(Dot11)
            if dot11.type != 0 or dot11.subtype != 12:
                return

            src = dot11.addr2
            if src is None:
                return
            if src.lower() in REGISTERED_BSSIDS:
                return  # discard AP echo

            bssid = dot11.addr3
            if bssid is None:
                return
            if bssid.lower() not in REGISTERED_BSSIDS:
                return  # only process packets for OUR networks

            rssi = None
            if pkt.haslayer(RadioTap):
                try:
                    rssi = getattr(pkt[RadioTap], "dBm_AntSignal", None)
                    if rssi is not None:
                        rssi = int(rssi)
                except (AttributeError, TypeError):
                    pass

            dst = dot11.addr1
            if dst is None:
                dst = "ff:ff:ff:ff:ff:ff"

            packet_dict = {
                "src_mac": src,
                "dst_mac": dst,
                "bssid": bssid,
                "rssi": rssi,
                "captured_at": datetime.utcnow().isoformat() + "Z",
            }

            _sniffer_packet_count += 1

            # Increment packet counter in DB
            try:
                db_execute("UPDATE system_stats SET total_packets = total_packets + 1 WHERE id = 1")
            except Exception:
                pass

            logger.info("[SNIFFER] captured src=%s bssid=%s (#%d)", src, bssid, _sniffer_packet_count)

            # Process synchronously in sniffer thread
            process_packet(packet_dict)

        except Exception as e:
            logger.error("[SNIFFER] error: %s", e)

    def _sniffer_loop():
        """Run sniffer in a loop with auto-restart on crash."""
        global _sniffer, _sniffer_running
        _sniffer_running = True
        while _sniffer_running:
            try:
                _sniffer = AsyncSniffer(
                    iface=INTERFACE,
                    prn=packet_handler,
                    store=False,
                    lfilter=lambda p: p.haslayer(Dot11Deauth),
                )
                _sniffer.start()
                logger.info("[SNIFFER] started on %s", INTERFACE)
                # Wait for the sniffer thread to finish (crash or stop)
                _sniffer.join()
            except Exception as e:
                logger.warning("[SNIFFER] crashed: %s", e)

            if _sniffer_running:
                logger.info("[SNIFFER] restarting in 3s...")
                time.sleep(3)
                # Bring interface back up just in case
                import subprocess
                subprocess.run(["ifconfig", INTERFACE, "up"], capture_output=True)

    # Start sniffer loop in a background daemon thread
    t = threading.Thread(target=_sniffer_loop, daemon=True)
    t.start()
    logger.info("[SNIFFER] started on %s", INTERFACE)


def stop_sniffer():
    """Stop the sniffer safely."""
    global _sniffer, _sniffer_running
    _sniffer_running = False
    if _sniffer:
        try:
            if hasattr(_sniffer, 'running') and _sniffer.running:
                _sniffer.stop()
        except Exception:
            pass
        logger.info("[SNIFFER] stopped")


def load_registered_bssids():
    """Load registered BSSIDs from the wifi_networks table."""
    global REGISTERED_BSSIDS
    try:
        rows = db_execute(
            "SELECT LOWER(bssid) as bssid FROM wifi_networks",
            fetch=True,
        )
        REGISTERED_BSSIDS = {row["bssid"] for row in rows}
    except Exception as e:
        logger.error("Failed to load BSSIDs: %s", e)
        REGISTERED_BSSIDS = set()


# ═══════════════════════════════════════════════════════════
# SECTION H — STATUS RESET BACKGROUND TASK
# ═══════════════════════════════════════════════════════════

def start_status_reset_task():
    """Background thread: check every 60s, reset to SAFE if no recent attacks."""
    def _loop():
        while True:
            time.sleep(60)
            try:
                now = datetime.utcnow()
                cutoff = (now - timedelta(minutes=10)).isoformat() + "Z"

                rows = db_execute(
                    """SELECT COUNT(*) as cnt FROM deauth_events
                       WHERE verdict IN ('ATTACK', 'CRITICAL')
                       AND first_seen >= %s AND resolved = 0""",
                    (cutoff,), fetch=True,
                )
                count = rows[0]["cnt"] if rows else 0

                if count == 0:
                    db_execute(
                        "UPDATE system_stats SET current_status = 'SAFE' WHERE id = 1"
                    )

                    # Clean up stale open_bursts
                    stale = [
                        mac for mac, burst in open_bursts.items()
                        if (now - burst["created_at"]).total_seconds() > 600
                    ]
                    for mac in stale:
                        del open_bursts[mac]

                    _broadcast_ws({"type": "status", "status": "SAFE"})

                    # Deactivate prevention
                    try:
                        requests.post(f"{PREVENTION_URL}/deactivate-all", json={}, timeout=3)
                    except Exception:
                        pass

                    logger.info("[STATUS] No recent attacks → SAFE")

            except Exception as e:
                logger.error("[STATUS] Reset check error: %s", e)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    logger.info("[STATUS] Reset task started (every 60s)")


# ═══════════════════════════════════════════════════════════
# SECTION I — PREVENTION BRIDGE
# ═══════════════════════════════════════════════════════════

def trigger_prevention(verdict: str, ml_score: float, final_score: float,
                       src_mac: str, bssid: str):
    """Activate prevention levels based on threat severity."""
    try:
        if final_score >= 50:
            requests.post(f"{PREVENTION_URL}/activate",
                          json={"level": 1, "final_score": final_score,
                                "ml_score": ml_score, "verdict": verdict},
                          timeout=3)
        if ml_score >= 60:
            requests.post(f"{PREVENTION_URL}/activate",
                          json={"level": 2, "final_score": final_score,
                                "ml_score": ml_score, "verdict": verdict},
                          timeout=3)
        if ml_score >= 85 or verdict == "CRITICAL":
            requests.post(f"{PREVENTION_URL}/activate",
                          json={"level": 3, "final_score": final_score,
                                "ml_score": ml_score, "verdict": verdict},
                          timeout=3)
    except Exception as e:
        logger.warning("[PREVENTION] Bridge error: %s", e)


# ═══════════════════════════════════════════════════════════
# WEBSOCKET BROADCAST
# ═══════════════════════════════════════════════════════════

def _broadcast_ws(message: dict):
    """Broadcast a message to all connected WebSocket clients."""
    import json
    dead = set()
    for ws in ws_clients:
        try:
            asyncio.run_coroutine_threadsafe(
                ws.send_json(message),
                asyncio.get_event_loop(),
            )
        except Exception:
            dead.add(ws)
    ws_clients -= dead


# ═══════════════════════════════════════════════════════════
# MODEL LOADING
# ═══════════════════════════════════════════════════════════

def load_models():
    """Load all 4 ML models from saved_models directory."""
    global models, scaler
    model_dir = os.path.join(os.path.dirname(__file__), "..", "ml-service", "saved_models")

    model_files = {
        "random_forest": "random_forest_model.pkl",
        "xgboost": "xgboost_model.pkl",
        "logistic_regression": "logistic_regression_model.pkl",
        "decision_tree": "decision_tree_model.pkl",
    }

    for name, filename in model_files.items():
        path = os.path.join(model_dir, filename)
        if os.path.exists(path):
            try:
                models[name] = joblib.load(path)
                logger.info("[ML] Loaded model: %s", name)
            except Exception as e:
                logger.error("[ML] Failed to load %s: %s", name, e)
        else:
            logger.warning("[ML] Model file not found: %s", path)

    # Load scaler
    scaler_path = os.path.join(model_dir, "standard_scaler.pkl")
    if os.path.exists(scaler_path):
        try:
            scaler = joblib.load(scaler_path)
            logger.info("[ML] Loaded scaler")
        except Exception as e:
            logger.warning("[ML] Failed to load scaler: %s", e)

    logger.info("[ML] %d/4 models loaded", len(models))


# ═══════════════════════════════════════════════════════════
# API FUNCTIONS (called by main.py FastAPI routes)
# ═══════════════════════════════════════════════════════════

def get_stats() -> dict:
    """Return unified stats for the API."""
    try:
        rows = db_execute("SELECT * FROM system_stats WHERE id = 1", fetch=True)
        stats = rows[0] if rows else {}
    except Exception:
        stats = {}

    # Calculate attacks in last 1 hour
    cutoff_1hr = (datetime.utcnow() - timedelta(hours=1)).isoformat() + "Z"
    try:
        rows = db_execute(
            """SELECT COUNT(*) as cnt FROM deauth_events
               WHERE verdict IN ('ATTACK', 'CRITICAL')
               AND first_seen >= %s AND resolved = 0""",
            (cutoff_1hr,), fetch=True,
        )
        attacks_1hr = rows[0]["cnt"] if rows else 0
    except Exception:
        attacks_1hr = 0

    # ML stats
    avg_conf = 0.0
    agreement_rate = 0.0
    try:
        resp = requests.get("http://localhost:5000/model-stats", timeout=2)
        if resp.status_code == 200:
            ml = resp.json()
            avg_conf = ml.get("average_confidence", 0.0)
            agreement_rate = ml.get("model_agreement_rate", 0.0)
    except Exception:
        pass

    return {
        "total_packets": stats.get("total_packets", 0),
        "total_events": stats.get("total_events", 0),
        "attack_events": stats.get("attack_events", 0),
        "critical_events": stats.get("critical_events", 0),
        "suspicious_events": stats.get("suspicious_events", 0),
        "current_status": stats.get("current_status", "SAFE"),
        "active_events": len(open_bursts),
        "attacks_1hr": attacks_1hr,
        "ml_models_loaded": len(models),
        "avg_confidence": round(avg_conf * 100, 1),
        "agreement_rate": round(agreement_rate * 100, 1),
    }


def get_events(limit: int = 50) -> list:
    """Return recent events."""
    try:
        rows = db_execute(
            "SELECT * FROM deauth_events ORDER BY first_seen DESC LIMIT %s",
            (limit,), fetch=True,
        )
        # Convert any non-serializable types
        for row in rows:
            for k, v in row.items():
                if isinstance(v, (datetime,)):
                    row[k] = v.isoformat()
        return rows
    except Exception as e:
        logger.error("Failed to get events: %s", e)
        return []


def clear_all():
    """Clear all detection data and reset counters."""
    global open_bursts, rate_tracker
    try:
        db_execute("DELETE FROM deauth_events")
        db_execute(
            """UPDATE system_stats SET
               total_packets = 0, total_events = 0,
               attack_events = 0, critical_events = 0,
               suspicious_events = 0, current_status = 'SAFE'
            WHERE id = 1"""
        )
        open_bursts = {}
        rate_tracker = {}

        # Deactivate prevention
        try:
            requests.post(f"{PREVENTION_URL}/deactivate-all", json={}, timeout=3)
        except Exception:
            pass

        # Reset ML stats
        try:
            requests.post("http://localhost:5000/reset-stats", timeout=2)
        except Exception:
            pass

        logger.info("[CLEAR] All detection data cleared")
        _broadcast_ws({"type": "status", "status": "SAFE"})
        return True
    except Exception as e:
        logger.error("Clear failed: %s", e)
        return False


def resolve_all():
    """Resolve all open events and reset status to SAFE."""
    global open_bursts
    try:
        db_execute(
            "UPDATE system_stats SET current_status = 'SAFE' WHERE id = 1"
        )
        db_execute(
            "UPDATE deauth_events SET resolved = 1 WHERE resolved = 0"
        )
        open_bursts = {}

        # Deactivate prevention
        try:
            requests.post(f"{PREVENTION_URL}/deactivate-all", json={}, timeout=3)
        except Exception:
            pass

        # Send resolved email
        try:
            requests.post(f"{BACKEND_URL}/api/detection/mark-resolved", timeout=3)
        except Exception:
            pass

        logger.info("[RESOLVE] All events resolved")
        _broadcast_ws({"type": "status", "status": "SAFE"})
        return True
    except Exception as e:
        logger.error("Resolve failed: %s", e)
        return False
