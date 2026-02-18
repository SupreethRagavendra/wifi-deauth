from datetime import datetime, timezone
import time

def calculate_packet_rate(timestamps: list) -> int:
    """
    Calculate packets per 5 seconds
    
    Args:
        timestamps: List of packet timestamps (last 100 packets)
    
    Returns:
        Packets per 5 seconds (integer)
        
    Logic:
        - Filter timestamps from last 5 seconds
        - Return count
    """
    if not timestamps:
        return 0
        
    current_time = time.time()
    # Filter timestamps that are within the last 5 seconds
    recent_packets = [t for t in timestamps if current_time - t <= 5]
    return len(recent_packets)

def calculate_sequence_gap(current_seq: int, last_seq: int) -> int:
    """
    Calculate gap between sequence numbers
    
    802.11 sequence numbers:
    - 12 bits (0-4095)
    - Wraps around after 4095
    
    Logic:
        - If current > last: return current - last
        - If current < last: return (4096 - last) + current (wraparound)
    """
    if current_seq >= last_seq:
        return current_seq - last_seq
    else:
        return (4096 - last_seq) + current_seq

def build_packet_json(packet_data: dict) -> dict:
    """
    Build JSON payload for backend
    
    Input example:
    {
        'source_mac': 'AA:BB:CC:DD:EE:FF',
        'dest_mac': '11:22:33:44:55:66',
        'bssid': '00:11:22:33:44:55',
        'sequence': 1234,
        'rssi': -47,
        'timestamp': 1737974400.123
    }
    
    Output format (MUST MATCH JAVA BACKEND):
    {
        "sourceMac": "AA:BB:CC:DD:EE:FF",
        "destMac": "11:22:33:44:55:66",
        "bssid": "00:11:22:33:44:55",
        "sequenceNumber": 1234,
        "rssi": -47,
        "timestamp": "2025-01-27T10:45:30.123Z",
        "frameType": "DEAUTH"
    }
    """
    # Convert timestamp to ISO 8601 format with Z (UTC)
    dt = datetime.fromtimestamp(packet_data.get('timestamp', time.time()), timezone.utc)
    iso_timestamp = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    
    return {
        "src": packet_data.get('source_mac', '00:00:00:00:00:00'),
        "dst": packet_data.get('dest_mac', '00:00:00:00:00:00'),
        "bssid": packet_data.get('bssid', '00:00:00:00:00:00'),
        "seq": packet_data.get('sequence', 0),
        "signal": packet_data.get('rssi', -100),
        "reason": packet_data.get('reason', 0),
        "channel": packet_data.get('channel', 0),
        "timestamp": iso_timestamp,
        "frameType": "DEAUTH"
    }
