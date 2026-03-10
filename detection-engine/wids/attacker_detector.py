"""
WIDS Attacker Detector — Research-Backed Detection Functions

Implements 8 detection methods from published research:
1. RSSI fingerprinting with AP beacon baseline
2. Beacon trap honeypots for attacker MAC identification
3. Traffic pattern correlation scoring
4. Multi-method voting system (2+ agree = high confidence)
5. Continuous MAC signature tracking
6. Sequence number gap analysis
7. Temporal protocol state mismatch detection

References:
- RSSI fingerprinting: deviation > max(3σ, 6dB) indicates spoofing
- Beacon traps: fake SSIDs capture attacker probe requests with real MAC
- Traffic correlation: MACs with no beacons + probes + recent appearance
- Voting: 2+ methods agreeing = high-confidence identification
- Temporal: deauth followed by assoc/EAPOL within 500ms = protocol violation
"""

import json
import logging
import statistics
import time
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

try:
    from scapy.all import (
        sniff, sendp, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth,
        Dot11Disas, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoResp,
        Dot11Auth, RadioTap, EAPOL, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger("WIDS.Detector")

# ====================================================================
# In-memory tracking structures (module-level singletons)
# ====================================================================

# Per-MAC packet history: mac -> [{"timestamp", "rssi", "frame_type", "seq"}, ...]
mac_signatures: Dict[str, List[Dict]] = defaultdict(list)

# Per-MAC activity counters: mac -> {"beacon_count", "deauth_count", "probe_count", ...}
mac_activity: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
    "beacon_count": 0,
    "deauth_count": 0,
    "probe_count": 0,
    "data_count": 0,
    "first_seen": None,
    "last_seen": None,
})

# Per-MAC sequence number state: mac -> {"last_seq": int, "gaps": []}
mac_sequence_state: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
    "last_seq": -1,
    "gaps": [],
})

# Per-MAC state timeline: mac -> [{"timestamp", "state"}, ...]
mac_state_timeline: Dict[str, List[Dict]] = defaultdict(list)

# Lock for thread-safe access
_tracking_lock = threading.Lock()

# Maximum packets to keep per MAC
MAX_PACKETS_PER_MAC = 200

# Maximum state transitions to keep per MAC
MAX_STATES_PER_MAC = 100


# ====================================================================
# 1. establish_ap_baseline
# ====================================================================

def establish_ap_baseline(
    ap_mac: str,
    interface: str,
    beacon_count: int = 50,
    timeout: int = 15,
    db=None,
) -> Dict[str, Any]:
    """
    Establish RSSI baseline for a target AP by capturing beacon frames.

    Captures `beacon_count` beacon frames from the AP using Scapy sniff,
    extracts RSSI via packet.dBm_AntSignal, and calculates statistics.

    Args:
        ap_mac: Target AP MAC address (e.g., "9E:A8:2C:C2:1F:D9")
        interface: Monitor mode interface (e.g., "wlan1mon")
        beacon_count: Number of beacon frames to capture (default 50)
        timeout: Max seconds to wait for beacons (default 15)
        db: Optional WIDSDatabase instance to persist the baseline

    Returns:
        Dict with keys: ap_mac, rssi_mean, rssi_stdev, rssi_min, rssi_max,
        sample_count, samples_raw, established_at
    """
    if not SCAPY_AVAILABLE:
        logger.error("Scapy not available — cannot establish baseline")
        return _empty_baseline(ap_mac)

    ap_mac_lower = ap_mac.lower()
    rssi_samples = []

    logger.info(
        "Establishing AP baseline: capturing %d beacons from %s on %s",
        beacon_count, ap_mac, interface,
    )

    def _beacon_handler(pkt):
        """Extract RSSI from beacon frames matching our AP."""
        if not pkt.haslayer(Dot11Beacon):
            return
        # Match AP MAC (addr2 = transmitter)
        src = pkt[Dot11].addr2
        if src and src.lower() == ap_mac_lower:
            rssi = _extract_rssi(pkt)
            if rssi is not None:
                rssi_samples.append(rssi)

    try:
        sniff(
            iface=interface,
            prn=_beacon_handler,
            stop_filter=lambda p: len(rssi_samples) >= beacon_count,
            timeout=timeout,
            store=False,
        )
    except Exception as e:
        logger.error("Beacon capture failed: %s", e)

    if len(rssi_samples) < 3:
        logger.warning(
            "Only captured %d beacons (need >= 3). Using fallback baseline.",
            len(rssi_samples),
        )
        return _empty_baseline(ap_mac)

    baseline = {
        "ap_mac": ap_mac,
        "rssi_mean": statistics.mean(rssi_samples),
        "rssi_stdev": statistics.stdev(rssi_samples) if len(rssi_samples) >= 2 else 3.0,
        "rssi_min": min(rssi_samples),
        "rssi_max": max(rssi_samples),
        "sample_count": len(rssi_samples),
        "samples_raw": rssi_samples,
        "established_at": datetime.now().isoformat(),
    }

    logger.info(
        "Baseline established: mean=%.1f dBm, stdev=%.1f dB (%d samples)",
        baseline["rssi_mean"], baseline["rssi_stdev"], baseline["sample_count"],
    )

    # Persist to database if available
    if db is not None:
        try:
            db.set_baseline(baseline)
        except Exception as e:
            logger.error("Failed to persist baseline: %s", e)

    return baseline


def _empty_baseline(ap_mac: str) -> Dict[str, Any]:
    """Return a placeholder baseline when capture fails."""
    return {
        "ap_mac": ap_mac,
        "rssi_mean": -50.0,
        "rssi_stdev": 5.0,
        "rssi_min": -60.0,
        "rssi_max": -40.0,
        "sample_count": 0,
        "samples_raw": [],
        "established_at": datetime.now().isoformat(),
    }


# ====================================================================
# 2. detect_by_rssi_fingerprinting
# ====================================================================

def detect_by_rssi_fingerprinting(
    deauth_rssi: Optional[float],
    ap_baseline: Dict[str, Any],
    candidate_macs: Optional[Dict[str, List[Dict]]] = None,
    deauth_time: Optional[float] = None,
) -> Tuple[Optional[str], float, bool]:
    """
    Detect spoofing via RSSI deviation from AP baseline.

    If the deauth frame's RSSI deviates from the AP's beacon baseline
    by more than max(3σ, 6dB), the frame is considered spoofed.
    Then searches known MAC signatures for a device with matching RSSI
    (±15dB) observed within ±1 second.

    Args:
        deauth_rssi: RSSI of the deauth frame (dBm), or None
        ap_baseline: Dict from establish_ap_baseline()
        candidate_macs: Optional dict of mac -> [{"timestamp", "rssi", ...}]
                        (defaults to module-level mac_signatures)
        deauth_time: Timestamp of the deauth frame (defaults to now)

    Returns:
        (attacker_mac, confidence, is_spoofed)
        - attacker_mac: MAC with matching RSSI, or None
        - confidence: 0-100
        - is_spoofed: True if RSSI deviates from baseline
    """
    if deauth_rssi is None:
        logger.debug("No RSSI on deauth frame — cannot fingerprint")
        return (None, 0.0, False)

    baseline_mean = ap_baseline.get("rssi_mean", -50.0)
    baseline_stdev = ap_baseline.get("rssi_stdev", 5.0)

    # Threshold = max(3σ, 6dB) per research
    threshold = max(baseline_stdev * 3, 6.0)

    # Calculate deviation
    deviation = abs(deauth_rssi - baseline_mean)
    is_spoofed = deviation > threshold

    logger.debug(
        "RSSI fingerprint: deauth=%.1f, baseline=%.1f±%.1f, "
        "deviation=%.1f, threshold=%.1f → %s",
        deauth_rssi, baseline_mean, baseline_stdev,
        deviation, threshold, "SPOOFED" if is_spoofed else "legitimate",
    )

    if not is_spoofed:
        return (None, 0.0, False)

    # Search for MAC with matching RSSI within ±15dB and ±1 second
    if candidate_macs is None:
        candidate_macs = mac_signatures

    if deauth_time is None:
        deauth_time = time.time()

    rssi_tolerance = 15.0  # dB
    time_tolerance = 1.0   # seconds

    best_mac = None
    best_confidence = 0.0

    with _tracking_lock:
        for mac, entries in candidate_macs.items():
            for entry in reversed(entries):  # most recent first
                entry_time = entry.get("timestamp", 0)
                entry_rssi = entry.get("rssi")

                if entry_rssi is None:
                    continue

                time_diff = abs(deauth_time - entry_time)
                if time_diff > time_tolerance:
                    continue

                rssi_diff = abs(deauth_rssi - entry_rssi)
                if rssi_diff <= rssi_tolerance:
                    # Confidence: closer RSSI match + tighter time = higher
                    rssi_score = max(0, 1.0 - rssi_diff / rssi_tolerance) * 50
                    time_score = max(0, 1.0 - time_diff / time_tolerance) * 30
                    spoof_bonus = 20.0 if is_spoofed else 0
                    confidence = min(100, rssi_score + time_score + spoof_bonus)

                    if confidence > best_confidence:
                        best_confidence = confidence
                        best_mac = mac

    return (best_mac, best_confidence, is_spoofed)


# ====================================================================
# 3. detect_by_beacon_trap
# ====================================================================

def detect_by_beacon_trap(
    interface: str,
    duration: int = 10,
    trap_ssids: Optional[List[str]] = None,
) -> Tuple[Optional[str], float]:
    """
    Deploy fake SSIDs as honeypots and capture probe requests.

    Broadcasts fake beacon frames for trap SSIDs, then captures any
    probe requests targeting those SSIDs. The probing device reveals
    its real MAC address (probe requests cannot use the spoofed MAC
    since the attacker's tool only spoofs deauth frames).

    Args:
        interface: Monitor mode interface
        duration: How long to run the trap (seconds)
        trap_ssids: List of fake SSIDs (defaults to enticing names)

    Returns:
        (attacker_mac, confidence)
        - attacker_mac: MAC that probed trap SSIDs, or None
        - confidence: 0-100 (50 + 15 per trap probed, capped at 95)
    """
    if not SCAPY_AVAILABLE:
        logger.error("Scapy not available — cannot deploy beacon trap")
        return (None, 0.0)

    if trap_ssids is None:
        trap_ssids = ["FREE_WIFI_5G", "ADMIN_NETWORK", "Guest_WiFi_Fast"]

    # Track which MACs probe which trap SSIDs
    trap_hits: Dict[str, set] = defaultdict(set)  # mac -> set of SSIDs probed
    trap_ssids_lower = {s.lower() for s in trap_ssids}

    logger.info(
        "Deploying beacon traps: %s on %s for %ds",
        trap_ssids, interface, duration,
    )

    # --- Step 1: Broadcast fake beacons in a background thread ---
    beacon_stop = threading.Event()

    def _broadcast_beacons():
        """Send fake beacon frames at 10/sec per SSID."""
        while not beacon_stop.is_set():
            for ssid in trap_ssids:
                # Build a fake beacon frame
                fake_mac = "DE:AD:BE:EF:00:%02X" % (hash(ssid) % 256)
                dot11 = Dot11(
                    type=0, subtype=8,
                    addr1="ff:ff:ff:ff:ff:ff",  # broadcast
                    addr2=fake_mac,              # transmitter
                    addr3=fake_mac,              # BSSID
                )
                beacon = Dot11Beacon(cap="ESS+privacy")
                essid = Dot11Elt(ID="SSID", info=ssid.encode(), len=len(ssid))
                rates = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
                dsset = Dot11Elt(ID="DSset", info=b"\x06")  # channel 6

                frame = RadioTap() / dot11 / beacon / essid / rates / dsset
                try:
                    sendp(frame, iface=interface, verbose=False, count=1)
                except Exception:
                    pass  # best-effort
            time.sleep(0.1)  # ~10 beacons/sec per SSID

    beacon_thread = threading.Thread(target=_broadcast_beacons, daemon=True)
    beacon_thread.start()

    # --- Step 2: Capture probe requests targeting trap SSIDs ---
    def _probe_handler(pkt):
        """Capture probe requests and check if they target trap SSIDs."""
        if not pkt.haslayer(Dot11ProbeReq):
            return
        # Extract probed SSID
        elt = pkt.getlayer(Dot11Elt)
        if elt is None:
            return
        try:
            probed_ssid = elt.info.decode("utf-8", errors="ignore")
        except (AttributeError, UnicodeDecodeError):
            return

        if probed_ssid.lower() in trap_ssids_lower:
            src_mac = pkt[Dot11].addr2
            if src_mac:
                trap_hits[src_mac.upper()].add(probed_ssid)
                logger.info(
                    "BEACON TRAP HIT: %s probed '%s'", src_mac.upper(), probed_ssid
                )

    try:
        sniff(
            iface=interface,
            prn=_probe_handler,
            timeout=duration,
            store=False,
        )
    except Exception as e:
        logger.error("Beacon trap capture failed: %s", e)
    finally:
        beacon_stop.set()
        beacon_thread.join(timeout=2)

    # --- Step 3: Find the MAC that probed the most trap SSIDs ---
    if not trap_hits:
        logger.info("No beacon trap hits — attacker not detected via traps")
        return (None, 0.0)

    # Sort by number of unique SSIDs probed
    best_mac = max(trap_hits, key=lambda m: len(trap_hits[m]))
    probe_count = len(trap_hits[best_mac])
    confidence = min(95, 50 + probe_count * 15)

    logger.info(
        "Beacon trap result: %s probed %d trap SSIDs → confidence %.0f%%",
        best_mac, probe_count, confidence,
    )

    return (best_mac, confidence)


# ====================================================================
# 4. detect_by_traffic_pattern
# ====================================================================

def detect_by_traffic_pattern(
    attack_time: float,
    activity: Optional[Dict[str, Dict]] = None,
    trusted_macs: Optional[List[str]] = None,
) -> Tuple[Optional[str], float]:
    """
    Correlate traffic patterns to identify the attacker.

    Scores each observed MAC address:
      +30 if no beacons (real APs send beacons; attackers don't)
      +25 if has probe requests (attacker scanning for targets)
      +20 if appeared recently (attacker just powered on)

    Excludes trusted MACs and MACs inactive for >10 seconds.

    Args:
        attack_time: Timestamp of the attack (time.time())
        activity: MAC activity dict (defaults to module-level mac_activity)
        trusted_macs: List of trusted MAC addresses to exclude

    Returns:
        (attacker_mac, confidence)
        - attacker_mac: MAC with score > 50, or None
        - confidence: min(85, score)
    """
    if activity is None:
        activity = mac_activity
    if trusted_macs is None:
        trusted_macs = []

    trusted_set = {m.upper() for m in trusted_macs}
    candidates = []

    with _tracking_lock:
        for mac, stats in activity.items():
            mac_upper = mac.upper()

            # Skip trusted devices
            if mac_upper in trusted_set:
                continue

            # Skip inactive MACs (last seen > 10 seconds ago)
            last_seen = stats.get("last_seen")
            if last_seen is None:
                continue
            if attack_time - last_seen > 10.0:
                continue

            score = 0

            # +30 if no beacons (attackers don't send beacons)
            if stats.get("beacon_count", 0) == 0:
                score += 30

            # +25 if has probe requests (attacker scanning)
            if stats.get("probe_count", 0) > 0:
                score += 25

            # +20 if recent appearance (first seen < 60 seconds ago)
            first_seen = stats.get("first_seen")
            if first_seen is not None and (attack_time - first_seen) < 60.0:
                score += 20

            if score > 0:
                candidates.append((mac_upper, score))

    if not candidates:
        logger.debug("Traffic pattern: no suspicious MACs found")
        return (None, 0.0)

    # Sort by score descending
    candidates.sort(key=lambda x: x[1], reverse=True)
    best_mac, best_score = candidates[0]

    if best_score <= 50:
        logger.debug("Traffic pattern: best score %d <= 50 (below threshold)", best_score)
        return (None, 0.0)

    confidence = min(85, best_score)

    logger.info(
        "Traffic pattern: %s scored %d → confidence %.0f%%",
        best_mac, best_score, confidence,
    )

    return (best_mac, confidence)


# ====================================================================
# 5. identify_attacker_voting_system
# ====================================================================

def identify_attacker_voting_system(
    deauth_rssi: Optional[float],
    attack_time: float,
    ap_baseline: Dict[str, Any],
    trusted_macs: Optional[List[str]] = None,
    interface: Optional[str] = None,
    run_beacon_trap: bool = False,
    beacon_trap_duration: int = 10,
) -> Tuple[Optional[str], float, str]:
    """
    Multi-method voting system for attacker identification.

    Runs up to 3 detection methods and combines results:
    - RSSI fingerprinting (always)
    - Traffic pattern correlation (always)
    - Beacon trap (optional, takes `beacon_trap_duration` seconds)

    Voting logic:
    - 2+ methods agree on same MAC: combine confidence, high certainty
    - 1 method only: return that result alone
    - No methods: return (None, 0, "UNKNOWN")

    Args:
        deauth_rssi: RSSI of the triggering deauth frame
        attack_time: Timestamp of the attack
        ap_baseline: AP RSSI baseline dict
        trusted_macs: Trusted MAC addresses to exclude
        interface: Monitor interface (needed for beacon trap)
        run_beacon_trap: Whether to run the slow beacon trap method
        beacon_trap_duration: Duration for beacon trap (seconds)

    Returns:
        (attacker_mac, combined_confidence, methods_string)
        - attacker_mac: identified MAC or None
        - combined_confidence: 0-100
        - methods_string: e.g. "RSSI+TRAFFIC_PATTERN" or "UNKNOWN"
    """
    if trusted_macs is None:
        trusted_macs = []

    results: List[Tuple[str, Optional[str], float]] = []

    # --- Method 1: RSSI Fingerprinting ---
    rssi_mac, rssi_conf, is_spoofed = detect_by_rssi_fingerprinting(
        deauth_rssi=deauth_rssi,
        ap_baseline=ap_baseline,
        deauth_time=attack_time,
    )
    if rssi_mac:
        results.append(("RSSI", rssi_mac, rssi_conf))
        logger.debug("Voting: RSSI → %s (%.0f%%)", rssi_mac, rssi_conf)

    # --- Method 2: Traffic Pattern ---
    traffic_mac, traffic_conf = detect_by_traffic_pattern(
        attack_time=attack_time,
        trusted_macs=trusted_macs,
    )
    if traffic_mac:
        results.append(("TRAFFIC_PATTERN", traffic_mac, traffic_conf))
        logger.debug("Voting: Traffic → %s (%.0f%%)", traffic_mac, traffic_conf)

    # --- Method 3: Beacon Trap (optional, slow) ---
    if run_beacon_trap and interface:
        trap_mac, trap_conf = detect_by_beacon_trap(
            interface=interface,
            duration=beacon_trap_duration,
        )
        if trap_mac:
            results.append(("BEACON_TRAP", trap_mac, trap_conf))
            logger.debug("Voting: Trap → %s (%.0f%%)", trap_mac, trap_conf)

    # --- Voting ---
    if not results:
        logger.info("Voting: no methods identified an attacker")
        return (None, 0.0, "UNKNOWN")

    # Count votes per MAC
    vote_counts: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
    for method, mac, conf in results:
        if mac:
            vote_counts[mac.upper()].append((method, conf))

    # Find MAC with most votes
    best_mac = None
    best_votes = []
    for mac, votes in vote_counts.items():
        if len(votes) > len(best_votes) or (
            len(votes) == len(best_votes)
            and sum(c for _, c in votes) > sum(c for _, c in best_votes)
        ):
            best_mac = mac
            best_votes = votes

    if best_mac is None:
        return (None, 0.0, "UNKNOWN")

    # Build methods string
    methods = [m for m, _ in best_votes]
    methods_str = "+".join(methods)

    # Combine confidence
    if len(best_votes) >= 2:
        # 2+ methods agree: average + agreement bonus
        avg_conf = sum(c for _, c in best_votes) / len(best_votes)
        agreement_bonus = 10 * (len(best_votes) - 1)  # +10 per extra method
        combined_conf = min(100, avg_conf + agreement_bonus)
    else:
        # Single method: use its confidence directly
        combined_conf = best_votes[0][1]

    logger.info(
        "Voting result: %s identified by %s → confidence %.0f%% (%d votes)",
        best_mac, methods_str, combined_conf, len(best_votes),
    )

    return (best_mac, combined_conf, methods_str)


# ====================================================================
# 6. continuous_mac_tracking
# ====================================================================

def continuous_mac_tracking(
    timestamp: float,
    src_mac: str,
    rssi: Optional[float],
    frame_type: str,
    seq_num: Optional[int] = None,
) -> None:
    """
    Track every observed packet for signature building.

    Called for ALL packets (beacons, probes, data, deauths).
    Maintains per-MAC history (last 200 packets) and activity counters.

    Args:
        timestamp: Packet capture timestamp (time.time())
        src_mac: Source MAC address
        rssi: Signal strength (dBm) or None
        frame_type: Frame type string ("beacon", "probe_req", "deauth", "data", etc.)
        seq_num: 802.11 sequence number (0-4095) or None
    """
    if not src_mac:
        return

    mac = src_mac.upper()

    entry = {
        "timestamp": timestamp,
        "rssi": rssi,
        "frame_type": frame_type,
        "seq_num": seq_num,
    }

    with _tracking_lock:
        # --- Update signature history ---
        sig_list = mac_signatures[mac]
        sig_list.append(entry)
        # Keep only the last MAX_PACKETS_PER_MAC entries
        if len(sig_list) > MAX_PACKETS_PER_MAC:
            mac_signatures[mac] = sig_list[-MAX_PACKETS_PER_MAC:]

        # --- Update activity counters ---
        activity = mac_activity[mac]
        if activity["first_seen"] is None:
            activity["first_seen"] = timestamp
        activity["last_seen"] = timestamp

        if frame_type == "beacon":
            activity["beacon_count"] += 1
        elif frame_type == "deauth" or frame_type == "disassoc":
            activity["deauth_count"] += 1
        elif frame_type == "probe_req":
            activity["probe_count"] += 1
        elif frame_type == "data":
            activity["data_count"] += 1

        # --- Update state timeline ---
        state_entry = {"timestamp": timestamp, "state": frame_type}
        timeline = mac_state_timeline[mac]
        timeline.append(state_entry)
        if len(timeline) > MAX_STATES_PER_MAC:
            mac_state_timeline[mac] = timeline[-MAX_STATES_PER_MAC:]


def flush_fingerprints_to_db(db) -> int:
    """
    Periodically flush in-memory MAC signatures to the database.

    Called by background task. Calculates RSSI statistics from the
    signature history and upserts to wids_fingerprints.

    Returns:
        Number of fingerprints updated.
    """
    count = 0

    with _tracking_lock:
        macs_to_flush = list(mac_signatures.keys())

    for mac in macs_to_flush:
        with _tracking_lock:
            entries = list(mac_signatures.get(mac, []))
            activity = dict(mac_activity.get(mac, {}))

        if not entries:
            continue

        # Calculate RSSI statistics
        rssi_values = [e["rssi"] for e in entries if e.get("rssi") is not None]
        frame_types = list(set(e["frame_type"] for e in entries if e.get("frame_type")))

        fp = {
            "mac_address": mac,
            "rssi_vector": rssi_values[-50:],  # last 50 samples
            "rssi_mean": statistics.mean(rssi_values) if rssi_values else None,
            "rssi_stdev": (
                statistics.stdev(rssi_values) if len(rssi_values) >= 2 else None
            ),
            "phase_offset": None,  # requires PHY-layer access
            "clock_skew": None,    # populated by clock_skew_tracker externally
            "packet_count": len(entries),
            "frame_types": frame_types,
            "spatial_coordinates": None,  # populated by trilateration externally
        }

        try:
            db.upsert_fingerprint(fp)
            count += 1
        except Exception as e:
            logger.error("Failed to flush fingerprint for %s: %s", mac, e)

    if count > 0:
        logger.debug("Flushed %d fingerprints to database", count)

    return count


# ====================================================================
# 7. detect_sequence_gap
# ====================================================================

def detect_sequence_gap(
    src_mac: str,
    seq_num: Optional[int],
    state: Optional[Dict[str, Dict]] = None,
) -> Optional[int]:
    """
    Detect sequence number anomalies indicating injection.

    802.11 sequence numbers are 0-4095 and increment by 1 per frame.
    Injection tools often:
    - Reset sequence to 0
    - Use sequence > 4000 (near wrap-around)
    - Cause large gaps (>100) between consecutive frames
    - Cause sudden resets from high to low

    Args:
        src_mac: Source MAC address
        seq_num: 802.11 sequence number (0-4095) or None
        state: Optional state dict (defaults to module-level mac_sequence_state)

    Returns:
        gap_size if anomaly detected, None otherwise
    """
    if seq_num is None:
        return None

    if state is None:
        state = mac_sequence_state

    mac = src_mac.upper()

    with _tracking_lock:
        mac_state = state[mac]
        last_seq = mac_state["last_seq"]

        # First packet from this MAC — just record it
        if last_seq < 0:
            mac_state["last_seq"] = seq_num
            return None

        # Calculate gap (handle wrap-around at 4096)
        if seq_num >= last_seq:
            gap = seq_num - last_seq
        else:
            # Wrap-around: e.g., 4090 → 5 = gap of 11 (mod 4096)
            gap = (4096 - last_seq) + seq_num

        mac_state["last_seq"] = seq_num

        # --- Anomaly checks ---
        anomaly_gap = None

        # Check 1: Sequence reset to 0 (injection tools default)
        if seq_num == 0 and last_seq > 100:
            anomaly_gap = last_seq
            logger.info(
                "SEQ ANOMALY: %s reset to 0 from %d", mac, last_seq
            )

        # Check 2: Sequence > 4000 (suspicious high range)
        elif seq_num > 4000 and last_seq < 100:
            anomaly_gap = gap
            logger.info(
                "SEQ ANOMALY: %s jumped to %d from %d", mac, seq_num, last_seq
            )

        # Check 3: Large gap (>100)
        elif gap > 100:
            anomaly_gap = gap
            logger.info(
                "SEQ ANOMALY: %s gap of %d (%d → %d)", mac, gap, last_seq, seq_num
            )

        # Check 4: Sudden reset from high to low (not wrap-around)
        elif last_seq > 2000 and seq_num < 50 and seq_num != 0:
            anomaly_gap = last_seq - seq_num
            logger.info(
                "SEQ ANOMALY: %s sudden reset %d → %d", mac, last_seq, seq_num
            )

        if anomaly_gap is not None:
            mac_state["gaps"].append({
                "timestamp": time.time(),
                "from_seq": last_seq,
                "to_seq": seq_num,
                "gap": anomaly_gap,
            })
            # Keep only last 20 gaps
            if len(mac_state["gaps"]) > 20:
                mac_state["gaps"] = mac_state["gaps"][-20:]

        return anomaly_gap


# ====================================================================
# 8. detect_temporal_mismatch
# ====================================================================

def detect_temporal_mismatch(
    src_mac: str,
    current_state: str,
    current_time: float,
    timeline: Optional[Dict[str, List[Dict]]] = None,
    window_ms: float = 500.0,
) -> bool:
    """
    Detect protocol state violations within a time window.

    If a deauth frame is followed by an association response or EAPOL
    frame from the same MAC within 500ms, the deauth was spoofed —
    a real deauthenticated client cannot immediately authenticate.

    Similarly, if a deauth for MAC X is followed by continued data
    frames from MAC X within the window, the deauth was spoofed.

    Args:
        src_mac: MAC address exhibiting the state transition
        current_state: Current frame type ("deauth", "assoc_resp", "eapol", "data")
        current_time: Timestamp of the current frame
        timeline: Per-MAC state timeline (defaults to module-level)
        window_ms: Temporal window in milliseconds (default 500)

    Returns:
        True if a protocol violation (temporal mismatch) is detected
    """
    if timeline is None:
        timeline = mac_state_timeline

    mac = src_mac.upper()
    window_sec = window_ms / 1000.0

    with _tracking_lock:
        mac_timeline = timeline.get(mac, [])
        if not mac_timeline:
            return False

        # Look backwards through the timeline for conflicting states
        for entry in reversed(mac_timeline):
            entry_time = entry.get("timestamp", 0)
            entry_state = entry.get("state", "")

            time_diff = current_time - entry_time
            if time_diff > window_sec:
                break  # Outside window
            if time_diff < 0:
                continue  # Future? Skip

            # Mismatch patterns:
            # 1. deauth followed by assoc_response → spoofed deauth
            if entry_state == "deauth" and current_state in ("assoc_resp", "assoc_response"):
                logger.info(
                    "TEMPORAL MISMATCH: %s sent deauth then assoc_resp within %.0fms",
                    mac, time_diff * 1000,
                )
                return True

            # 2. deauth followed by EAPOL → spoofed deauth
            if entry_state == "deauth" and current_state == "eapol":
                logger.info(
                    "TEMPORAL MISMATCH: %s sent deauth then EAPOL within %.0fms",
                    mac, time_diff * 1000,
                )
                return True

            # 3. deauth followed by data frames → spoofed deauth
            if entry_state == "deauth" and current_state == "data":
                logger.info(
                    "TEMPORAL MISMATCH: %s sent deauth then data within %.0fms",
                    mac, time_diff * 1000,
                )
                return True

            # 4. assoc_resp followed by deauth → spoofed deauth
            if entry_state in ("assoc_resp", "assoc_response") and current_state == "deauth":
                logger.info(
                    "TEMPORAL MISMATCH: %s sent assoc_resp then deauth within %.0fms",
                    mac, time_diff * 1000,
                )
                return True

            # 5. EAPOL followed by deauth → spoofed deauth
            if entry_state == "eapol" and current_state == "deauth":
                logger.info(
                    "TEMPORAL MISMATCH: %s sent EAPOL then deauth within %.0fms",
                    mac, time_diff * 1000,
                )
                return True

    return False


# ====================================================================
# Helpers
# ====================================================================

def _extract_rssi(pkt) -> Optional[float]:
    """Extract RSSI from a Scapy packet (RadioTap header)."""
    try:
        if pkt.haslayer(RadioTap):
            rssi = getattr(pkt[RadioTap], "dBm_AntSignal", None)
            if rssi is not None:
                return float(rssi)
    except Exception:
        pass
    return None


def _classify_frame_type(pkt) -> str:
    """Classify a Dot11 packet into a frame type string."""
    if not pkt.haslayer(Dot11):
        return "unknown"

    frame_type = pkt[Dot11].type
    frame_subtype = pkt[Dot11].subtype

    if frame_type == 0:  # Management
        subtypes = {
            0: "assoc_req",
            1: "assoc_resp",
            2: "reassoc_req",
            3: "reassoc_resp",
            4: "probe_req",
            5: "probe_resp",
            8: "beacon",
            10: "disassoc",
            11: "auth",
            12: "deauth",
        }
        return subtypes.get(frame_subtype, f"mgmt_{frame_subtype}")
    elif frame_type == 1:  # Control
        return "control"
    elif frame_type == 2:  # Data
        if pkt.haslayer(EAPOL):
            return "eapol"
        return "data"
    return "unknown"


def get_tracking_stats() -> Dict[str, Any]:
    """Return current tracking statistics for debugging."""
    with _tracking_lock:
        return {
            "tracked_macs": len(mac_signatures),
            "total_packets": sum(len(v) for v in mac_signatures.values()),
            "active_macs": sum(
                1 for v in mac_activity.values()
                if v.get("last_seen") and time.time() - v["last_seen"] < 60
            ),
            "sequence_states": len(mac_sequence_state),
            "state_timelines": len(mac_state_timeline),
        }


def reset_tracking() -> None:
    """Reset all in-memory tracking structures. Used for testing."""
    with _tracking_lock:
        mac_signatures.clear()
        mac_activity.clear()
        mac_sequence_state.clear()
        mac_state_timeline.clear()
    logger.info("All tracking structures reset")
