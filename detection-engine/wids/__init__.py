"""
WIDS — WiFi Intrusion Detection System (Part 1: Detection Engine)

Research-backed deauthentication attack detection using:
- RSSI fingerprinting with AP baseline deviation
- Beacon trap honeypots for attacker MAC identification
- Traffic pattern correlation and voting system
- Sequence number gap analysis
- Temporal state mismatch detection
"""

from .database import WIDSDatabase
from .config_manager import ConfigManager
from .attacker_detector import (
    establish_ap_baseline,
    detect_by_rssi_fingerprinting,
    detect_by_beacon_trap,
    detect_by_traffic_pattern,
    identify_attacker_voting_system,
    continuous_mac_tracking,
    detect_sequence_gap,
    detect_temporal_mismatch,
)

__all__ = [
    "WIDSDatabase",
    "ConfigManager",
    "establish_ap_baseline",
    "detect_by_rssi_fingerprinting",
    "detect_by_beacon_trap",
    "detect_by_traffic_pattern",
    "identify_attacker_voting_system",
    "continuous_mac_tracking",
    "detect_sequence_gap",
    "detect_temporal_mismatch",
]
