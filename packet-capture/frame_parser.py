from datetime import datetime, timezone
import time


def calculate_packet_rate(timestamps: list) -> int:
    """
    Calculate packets per 5 seconds
    """
    if not timestamps:
        return 0
        
    current_time = time.time()
    recent_packets = [t for t in timestamps if current_time - t <= 5]
    return len(recent_packets)


def calculate_sequence_gap(current_seq: int, last_seq: int) -> int:
    """
    Calculate gap between 802.11 sequence numbers (12-bit, 0-4095).
    """
    if current_seq >= last_seq:
        return current_seq - last_seq
    else:
        return (4096 - last_seq) + current_seq


def build_packet_json(packet_data: dict, rssi_analysis: dict = None) -> dict:
    """
    Build JSON payload for backend.
    
    Now includes RSSI analysis fields from RSSITracker when available.
    """
    # Convert timestamp to ISO 8601
    dt = datetime.fromtimestamp(packet_data.get('timestamp', time.time()))
    iso_timestamp = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
    
    result = {
        "src": packet_data.get('source_mac', '00:00:00:00:00:00'),
        "dst": packet_data.get('dest_mac', '00:00:00:00:00:00'),
        "bssid": packet_data.get('bssid', '00:00:00:00:00:00'),
        "seq": packet_data.get('sequence', 0),
        "signal": packet_data.get('rssi', -100),
        "reason": packet_data.get('reason', 0),
        "channel": packet_data.get('channel', 0),
        "timestamp": iso_timestamp,
        "frameType": "DEAUTH",
    }

    # ── Attack Detection Fields (from RSSITracker) ─────────────────────
    if rssi_analysis:
        result["isSpoofed"] = rssi_analysis.get("attack_confirmed", False)
        result["realAttackerMac"] = rssi_analysis.get("real_attacker_mac", "00:00:00:00:00:00")
        result["rssiDeviation"] = rssi_analysis.get("rssi_deviation", 0.0)
        result["apBaselineRssi"] = rssi_analysis.get("ap_baseline_rssi", 0.0)
        result["detectionMethod"] = rssi_analysis.get("detection_method", "NONE")
        result["scoreBoost"] = rssi_analysis.get("score_boost", 0)
        result["attackConfidence"] = rssi_analysis.get("attack_confidence", 0)
        result["attackRate"] = rssi_analysis.get("attack_rate", 0.0)
        result["uniqueVictims"] = rssi_analysis.get("unique_victims", 0)
        result["totalDeauths"] = rssi_analysis.get("total_deauths", 0)

    return result
