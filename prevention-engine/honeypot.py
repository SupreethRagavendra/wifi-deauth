"""
prevention-engine/honeypot.py
Perfect Clone Honeypot + Fake AP Beacon Flood

╔══════════════════════════════════════════════════════════════════╗
║  DUAL-LAYER DECEPTION                                          ║
║                                                                ║
║  Layer 1: 150+ Fake APs with similar SSIDs (Scapy beacons)    ║
║           Attacker wastes time scanning / choosing AP           ║
║                                                                ║
║  Layer 2: 15 Perfect Client Clones (last-byte MAC variants)    ║
║           Even if attacker finds real BSSID, all clients       ║
║           look identical — deauths hit clones, NOT real device ║
║                                                                ║
║  Layer 3: Silent Protection for real client (1500 fps reassoc) ║
║           Real client is invisible and protected               ║
╚══════════════════════════════════════════════════════════════════╝

Start/stop via REST API:
  POST /honeypot/start
  POST /honeypot/stop
  GET  /honeypot/status
"""

import os
import subprocess
import random
import string
import logging
import threading
import time
import yaml

# ── Config ──
_CFG_PATH = os.path.join(os.path.dirname(__file__), "config.yml")

def _load_config():
    try:
        with open(_CFG_PATH) as f:
            return yaml.safe_load(f)
    except Exception:
        return {}

_cfg = _load_config()
_hp_cfg = _cfg.get("honeypot", {})
_net_cfg = _cfg.get("network", {})

IFACE         = _hp_cfg.get("interface", _net_cfg.get("interface", "wlan1"))  # Honeypot uses its own interface
REAL_AP_MAC   = _net_cfg.get("ap_mac",     "9E:A8:2C:C2:1F:D9").lower()
REAL_CLIENT   = _net_cfg.get("client_mac", "4C:6F:9C:F4:FA:63").lower()
CHANNEL       = _net_cfg.get("channel", 11)
SSID          = _net_cfg.get("ssid", "supreeth")

# Clone settings
NUM_CLONES          = _hp_cfg.get("num_clones", 15)
REAL_CLIENT_RSSI    = _hp_cfg.get("real_client_rssi", -52)
RSSI_VARIANCE       = _hp_cfg.get("rssi_variance", 8)
SILENT_PROTECT_FPS  = _hp_cfg.get("silent_protection_fps", 1500)
DECOY_VISIBLE_FPS   = _hp_cfg.get("decoy_visible_fps", 50)

# Fake AP settings
FAKE_AP_COUNT       = _hp_cfg.get("fake_ap_count", 150)
BEACON_INTERVAL_MS  = _hp_cfg.get("beacon_interval_ms", 20)
SSID_VARIANTS       = _hp_cfg.get("ssid_variants", [
    "supreeth_guest", "supreeth_5G", "supreeth_ext", "supreeth_2G",
    "supreeth_office", "SUPREETH", "supreeth-5ghz", "supreeth_IoT",
    "supreeth_backup", "supreeth_secure", "supreeth_WiFi", "supreeth_home",
    "supreeth_net", "supreeth-secure", "supreeth_vpn",
])

# ── Logger ──
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
hp_log = logging.getLogger("honeypot")
hp_log.setLevel(logging.DEBUG)
if not hp_log.handlers:
    fh = logging.FileHandler(os.path.join(LOG_DIR, "honeypot.log"))
    fh.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
    hp_log.addHandler(fh)

# ── State ──
_state = {
    "active": False,
    "fake_aps": 0,
    "fake_clients": 0,
    "clones": [],
    "fake_ap_list": [],
    "threads": [],
    "deauths_absorbed": 0,
    "protection_frames_sent": 0,
    "clone_frames_sent": 0,
    "beacon_frames_sent": 0,
    "stop_event": None,
}


# ═══════════════════════════════════════════════════════════════════════
# MAC HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _random_mac():
    """Generate a random locally-administered unicast MAC."""
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] | 0x02) & 0xFE
    return ":".join(f"{b:02x}" for b in octets)


def _nearby_mac(base_mac: str, offset: int) -> str:
    """Generate MAC with last byte offset from base."""
    parts = base_mac.lower().split(":")
    prefix = ":".join(parts[:5])
    last_byte = int(parts[5], 16)
    new_byte = (last_byte + offset) % 256
    return f"{prefix}:{new_byte:02x}"


# ═══════════════════════════════════════════════════════════════════════
# LAYER 1: FAKE AP BEACON FLOOD (150+ fake APs with similar SSIDs)
# ═══════════════════════════════════════════════════════════════════════

def _generate_fake_aps(count: int):
    """Generate fake AP list: (bssid, ssid, channel, rssi)."""
    aps = []
    used_macs = {REAL_AP_MAC, REAL_CLIENT}

    for i in range(count):
        # Generate random BSSID
        while True:
            mac = _random_mac()
            if mac not in used_macs:
                used_macs.add(mac)
                break

        # Pick SSID — use variants first, then generate random ones
        if i < len(SSID_VARIANTS):
            ssid = SSID_VARIANTS[i]
        else:
            suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(2, 5)))
            templates = [
                f"{SSID}_{suffix}", f"{SSID}-{suffix}", f"{SSID}{suffix}",
                f"{SSID.upper()}_{suffix}", f"{SSID}_AP{i}",
                f"{SSID}_Room{random.randint(1, 20)}",
                f"{SSID}_{random.choice(['2G', '5G', '6E', 'AC', 'AX'])}",
            ]
            ssid = random.choice(templates)

        # Random channel (mostly same channel, some nearby)
        ch = CHANNEL if random.random() < 0.7 else random.choice([1, 6, 11])
        rssi = random.randint(-65, -35)

        aps.append({"bssid": mac, "ssid": ssid, "channel": ch, "rssi": rssi})

    return aps


def _beacon_flood_worker(fake_aps, stop_event):
    """
    Continuously broadcast beacon frames for all fake APs.
    Each fake AP appears as a real network in airodump-ng.
    """
    try:
        from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp
    except ImportError:
        hp_log.error("scapy not available for beacon flood")
        return

    interval = BEACON_INTERVAL_MS / 1000.0

    while not stop_event.is_set():
        try:
            # Pick a random batch of APs to beacon this cycle
            batch = random.sample(fake_aps, min(10, len(fake_aps)))

            frames = []
            for ap in batch:
                beacon = (
                    RadioTap(present="dBm_AntSignal", dBm_AntSignal=ap["rssi"]) /
                    Dot11(type=0, subtype=8,
                          addr1="ff:ff:ff:ff:ff:ff",
                          addr2=ap["bssid"],
                          addr3=ap["bssid"]) /
                    Dot11Beacon(cap="ESS+privacy") /
                    Dot11Elt(ID="SSID", info=ap["ssid"].encode()) /
                    Dot11Elt(ID="DSset", info=bytes([ap["channel"]])) /
                    Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24") /
                    Dot11Elt(ID="RSNinfo", info=bytes([
                        1, 0,                     # RSN Version 1
                        0x00, 0x0f, 0xac, 0x04,   # CCMP
                        1, 0,                     # 1 pairwise
                        0x00, 0x0f, 0xac, 0x04,   # CCMP
                        1, 0,                     # 1 auth
                        0x00, 0x0f, 0xac, 0x02,   # PSK
                    ]))
                )
                frames.append(beacon)

            sendp(frames, iface=IFACE, verbose=0, inter=interval)
            _state["beacon_frames_sent"] += len(frames)

        except Exception:
            time.sleep(0.5)


# ═══════════════════════════════════════════════════════════════════════
# LAYER 2: PERFECT CLIENT CLONES (last-byte MAC variants)
# ═══════════════════════════════════════════════════════════════════════

def _generate_clones(real_mac: str, count: int):
    """
    Generate clones with last byte ±1..±10 from the real client MAC.

    Real:   4c:6f:9c:f4:fa:63
    Clone1: 4c:6f:9c:f4:fa:64  (offset +1)
    Clone2: 4c:6f:9c:f4:fa:62  (offset -1)

    Attacker sees 15+ devices with nearly identical MACs — 
    "Which one is real??" → ALL attacks hit clones!
    """
    offsets = []
    for off in [-3, -2, -1, +1, +2, +3]:
        offsets.append(off)
    extras = [-10, -9, -8, -7, -6, -5, -4, +4, +5, +6, +7, +8, +9, +10]
    random.shuffle(extras)
    for off in extras:
        if off not in offsets:
            offsets.append(off)

    clones = []
    for off in offsets[:count]:
        clone_mac = _nearby_mac(real_mac, off)
        clone_rssi = REAL_CLIENT_RSSI + random.randint(-RSSI_VARIANCE // 2, RSSI_VARIANCE // 2)
        clones.append({"mac": clone_mac, "offset": off, "rssi": clone_rssi})

    return clones


def _decoy_worker(clone_info, stop_event):
    """Each clone sends visible 802.11 frames with strong RSSI (50fps)."""
    try:
        from scapy.all import RadioTap, Dot11, Dot11Auth, Dot11AssoResp, sendp
    except ImportError:
        return

    mac = clone_info["mac"]
    rssi = clone_info["rssi"]
    ap = REAL_AP_MAC

    while not stop_event.is_set():
        try:
            frames = [
                # Auth (visible RSSI)
                RadioTap(present="dBm_AntSignal", dBm_AntSignal=rssi) /
                Dot11(addr1=ap, addr2=mac, addr3=ap) /
                Dot11Auth(algo=0, seqnum=2, status=0),
                # Association
                RadioTap(present="dBm_AntSignal", dBm_AntSignal=rssi) /
                Dot11(addr1=mac, addr2=ap, addr3=ap) /
                Dot11AssoResp(cap="ESS+privacy", status=0, AID=random.randint(1, 50)),
                # Null data keepalive (highly visible in airodump)
                RadioTap(present="dBm_AntSignal", dBm_AntSignal=rssi) /
                Dot11(type=2, subtype=4, addr1=ap, addr2=mac, addr3=ap),
            ]
            for frame in frames:
                sendp(frame, iface=IFACE, verbose=0)
                _state["clone_frames_sent"] += 1
                time.sleep(1.0 / DECOY_VISIBLE_FPS)
        except Exception:
            time.sleep(0.5)


# ═══════════════════════════════════════════════════════════════════════
# LAYER 3: SILENT PROTECTION (real client — invisible 1500fps reassoc)
# ═══════════════════════════════════════════════════════════════════════

def _silent_protection_worker(stop_event):
    """Send auth/reassoc frames for the real client at max FPS (invisible)."""
    try:
        from scapy.all import Dot11, Dot11Auth, Dot11AssoResp, Dot11ReassoResp, sendp
    except ImportError:
        return

    sleep_time = 1.0 / SILENT_PROTECT_FPS
    ap = REAL_AP_MAC
    client = REAL_CLIENT

    while not stop_event.is_set():
        try:
            frames = [
                Dot11(addr1=ap, addr2=client, addr3=ap) /
                Dot11Auth(algo=0, seqnum=random.randint(1, 65535), status=0),
                Dot11(addr1=client, addr2=ap, addr3=ap) /
                Dot11AssoResp(cap="ESS+privacy", status=0, AID=random.randint(1, 2007)),
                Dot11(addr1=client, addr2=ap, addr3=ap) /
                Dot11ReassoResp(cap="ESS+privacy", status=0, AID=random.randint(1, 2007)),
            ]
            sendp(frames, iface=IFACE, verbose=0, inter=0)
            _state["protection_frames_sent"] += len(frames)
            time.sleep(sleep_time)
        except Exception:
            time.sleep(0.1)


# ═══════════════════════════════════════════════════════════════════════
# DEAUTH ABSORBER — sniff deauths on clones, instant reconnect
# ═══════════════════════════════════════════════════════════════════════

def _deauth_absorber(stop_event, clones):
    """Sniff deauths targeting clones and instantly reconnect them."""
    try:
        from scapy.all import (
            RadioTap, Dot11, Dot11Deauth, Dot11Disas,
            Dot11Auth, Dot11AssoResp, sniff, sendp,
        )
    except ImportError:
        return

    clone_macs = {c["mac"]: c for c in clones}
    ap = REAL_AP_MAC

    def _handle_pkt(pkt):
        if not pkt.haslayer(Dot11):
            return
        if not (pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas)):
            return
        dst = pkt[Dot11].addr1
        if dst and dst.lower() in clone_macs:
            _state["deauths_absorbed"] += 1
            clone = clone_macs[dst.lower()]
            rssi = clone["rssi"]
            # Instant reconnect flood — attacker thinks deauth failed
            reconnect = [
                RadioTap(present="dBm_AntSignal", dBm_AntSignal=rssi) /
                Dot11(addr1=ap, addr2=dst, addr3=ap) /
                Dot11Auth(algo=0, seqnum=2, status=0),
                RadioTap(present="dBm_AntSignal", dBm_AntSignal=rssi) /
                Dot11(addr1=dst, addr2=ap, addr3=ap) /
                Dot11AssoResp(cap="ESS+privacy", status=0, AID=1),
            ]
            try:
                sendp(reconnect * 50, iface=IFACE, verbose=0, inter=0.001)
            except Exception:
                pass
            hp_log.info(f"Deauth absorbed: clone {dst} (offset {clone['offset']:+d}) — #{_state['deauths_absorbed']}")

    # Continuous sniff loop
    while not stop_event.is_set():
        try:
            sniff(iface=IFACE, prn=_handle_pkt, store=0,
                  stop_filter=lambda _: stop_event.is_set(), timeout=5)
        except Exception:
            time.sleep(1)


# ═══════════════════════════════════════════════════════════════════════
# INTERFACE SETUP
# ═══════════════════════════════════════════════════════════════════════

def _setup_interface():
    """Put wlan1 into monitor mode on the correct channel."""
    cmds = [
        f"ip link set {IFACE} down",
        f"iw dev {IFACE} set monitor none",
        f"ip link set {IFACE} up",
        f"iw dev {IFACE} set channel {CHANNEL}",
        f"iw dev {IFACE} set txpower fixed 3000",
    ]
    for cmd in cmds:
        subprocess.run(cmd.split(), capture_output=True, timeout=5)
    hp_log.info(f"Interface {IFACE} → monitor mode (channel {CHANNEL})")


# ═══════════════════════════════════════════════════════════════════════
# PUBLIC API — start() / stop() / get_status()
# ═══════════════════════════════════════════════════════════════════════

def start():
    """
    Activate dual-layer honeypot:
      Layer 1: 150+ fake APs (beacon flood)
      Layer 2: 15 perfect client clones
      Layer 3: Silent protection for real client
    """
    if _state["active"]:
        return {"ok": True, "status": get_status(), "msg": "Already active"}

    hp_log.info("Starting dual-layer honeypot (fake APs + perfect clones)...")

    # Setup interface
    try:
        _setup_interface()
    except Exception as e:
        hp_log.warning(f"Interface setup issue (may still work): {e}")

    # Generate fake APs
    fake_aps = _generate_fake_aps(FAKE_AP_COUNT)
    _state["fake_ap_list"] = fake_aps

    # Generate perfect client clones
    clones = _generate_clones(REAL_CLIENT, NUM_CLONES)
    _state["clones"] = clones

    # Reset counters
    _state["deauths_absorbed"] = 0
    _state["protection_frames_sent"] = 0
    _state["clone_frames_sent"] = 0
    _state["beacon_frames_sent"] = 0

    stop_event = threading.Event()
    _state["stop_event"] = stop_event
    threads = []

    # ── Layer 1: Fake AP beacon flood (5 threads, each beacons a batch) ──
    for i in range(5):
        chunk_size = len(fake_aps) // 5
        chunk = fake_aps[i * chunk_size : (i + 1) * chunk_size]
        if i == 4:
            chunk = fake_aps[i * chunk_size:]  # Include remainder
        t = threading.Thread(target=_beacon_flood_worker, args=(chunk, stop_event), daemon=True)
        t.start()
        threads.append(t)
    hp_log.info(f"Layer 1: {len(fake_aps)} fake APs beaconing (5 threads)")

    # ── Layer 2: Perfect client clone decoys (1 thread per clone) ──
    for clone in clones:
        t = threading.Thread(target=_decoy_worker, args=(clone, stop_event), daemon=True)
        t.start()
        threads.append(t)
    hp_log.info(f"Layer 2: {len(clones)} perfect client clones active")

    # ── Layer 3: Silent protection for real client (10 threads) ──
    for _ in range(10):
        t = threading.Thread(target=_silent_protection_worker, args=(stop_event,), daemon=True)
        t.start()
        threads.append(t)
    hp_log.info("Layer 3: 10 silent protection threads for real client")

    # ── Deauth absorber ──
    t = threading.Thread(target=_deauth_absorber, args=(stop_event, clones), daemon=True)
    t.start()
    threads.append(t)

    _state["threads"] = threads
    _state["active"] = True
    _state["fake_aps"] = FAKE_AP_COUNT
    _state["fake_clients"] = NUM_CLONES

    # Log to DB
    try:
        import db
        db.log_honeypot("start", FAKE_AP_COUNT, NUM_CLONES)
    except Exception as e:
        hp_log.warning(f"DB log failed: {e}")

    hp_log.info(
        f"Honeypot ACTIVE: {FAKE_AP_COUNT} fake APs + {NUM_CLONES} client clones + "
        f"10 protection threads + deauth absorber"
    )
    return {"ok": True, "status": get_status()}


def stop():
    """Deactivate honeypot: signal all threads to stop."""
    if not _state["active"]:
        return {"ok": True, "status": get_status(), "msg": "Already inactive"}

    hp_log.info("Stopping dual-layer honeypot...")

    if _state["stop_event"]:
        _state["stop_event"].set()

    time.sleep(1)

    _state["active"] = False
    _state["fake_aps"] = 0
    _state["fake_clients"] = 0
    _state["clones"] = []
    _state["fake_ap_list"] = []
    _state["threads"] = []
    _state["stop_event"] = None

    # Log to DB
    try:
        import db
        db.log_honeypot("stop")
    except Exception as e:
        hp_log.warning(f"DB log failed: {e}")

    hp_log.info("Honeypot stopped")
    return {"ok": True, "status": get_status()}


def get_status():
    """Return current honeypot status dict (compatible with dashboard)."""
    num_fake_aps = _state["fake_aps"]
    num_clones = len(_state["clones"])

    # With fake APs, attacker must find real AP among 1 + num_fake_aps
    total_visible = 1 + num_fake_aps
    ap_prob = (1 / total_visible * 100) if total_visible > 1 else 100.0

    # Even after finding real AP, must find real client among 1 + num_clones
    total_clients = 1 + num_clones
    both_prob = (1 / total_visible) * (1 / total_clients) * 100 if total_visible > 1 else 100.0

    return {
        "active": _state["active"],
        "fake_aps": num_fake_aps,
        "fake_clients": num_clones,
        "total_visible_networks": total_visible,
        "attack_probability_pct": round(ap_prob, 4),
        "both_probability_pct": round(both_prob, 4),
        "deauths_absorbed": _state["deauths_absorbed"],
        "protection_frames": _state["protection_frames_sent"],
        "clone_frames": _state["clone_frames_sent"],
        "beacon_frames": _state["beacon_frames_sent"],
    }
