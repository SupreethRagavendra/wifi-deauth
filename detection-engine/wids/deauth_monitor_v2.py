#!/usr/bin/env python3
"""
WIDS Deauth Monitor V2 — Main Packet Handler

Scapy-based packet handler integrating all detection methods:
- Continuous MAC tracking on every packet
- Deauth/disassoc detection pipeline with RSSI, sequence, temporal checks
- Multi-method voting for attacker identification
- Sliding window frame counting
- Prevention level calculation
- Background housekeeping (expire events, cleanup blocks, flush fingerprints)

Usage:
    python deauth_monitor_v2.py [--interface wlan1mon] [--db-host localhost]

On startup:
    1. Load config from wids_config table
    2. Establish AP RSSI baseline (50 beacons, ~5 sec)
    3. Initialize tracking structures

On every packet:
    1. continuous_mac_tracking()
    2. If deauth/disassoc: full detection pipeline → insert wids_events

Background (every 10 seconds):
    1. Mark events > 60s old as inactive
    2. Remove expired blocks
    3. Flush fingerprints to database
"""

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import (
        sniff, Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas,
        Dot11ProbeReq, RadioTap, EAPOL, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Add parent directory to path for relative imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import WIDSDatabase
from config_manager import ConfigManager
from attacker_detector import (
    establish_ap_baseline,
    detect_by_rssi_fingerprinting,
    detect_by_traffic_pattern,
    identify_attacker_voting_system,
    continuous_mac_tracking,
    detect_sequence_gap,
    detect_temporal_mismatch,
    flush_fingerprints_to_db,
    get_tracking_stats,
    reset_tracking,
    _extract_rssi,
    _classify_frame_type,
    mac_signatures,
    mac_activity,
)

# ====================================================================
# Logging setup
# ====================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("WIDS.Monitor")

# ====================================================================
# Sliding window for frame counting
# ====================================================================
# Per-MAC deauth timestamps for 5-second sliding window
_deauth_timestamps: dict = defaultdict(list)
_deauth_lock = threading.Lock()


def _count_frames_in_window(src_mac: str, window_sec: int = 5) -> int:
    """Count deauth frames from src_mac in the last `window_sec` seconds."""
    now = time.time()
    cutoff = now - window_sec

    with _deauth_lock:
        timestamps = _deauth_timestamps[src_mac]
        # Prune old entries
        timestamps[:] = [t for t in timestamps if t > cutoff]
        return len(timestamps)


def _record_deauth_frame(src_mac: str) -> None:
    """Record a deauth frame timestamp for sliding window counting."""
    with _deauth_lock:
        _deauth_timestamps[src_mac].append(time.time())


# ====================================================================
# Prevention level calculation
# ====================================================================

def _calculate_prevention_level(
    confidence: float, thresholds: dict
) -> int:
    """
    Determine prevention level (0-4) from attacker confidence.

    Level 0: No prevention (confidence below level1)
    Level 1: Monitor + log (confidence >= level1)
    Level 2: Active defense (confidence >= level2)
    Level 3: Full defense  (confidence >= level3)
    Level 4: Maximum       (confidence >= level4)
    """
    if confidence >= thresholds.get("level4", 95):
        return 4
    elif confidence >= thresholds.get("level3", 85):
        return 3
    elif confidence >= thresholds.get("level2", 60):
        return 2
    elif confidence >= thresholds.get("level1", 40):
        return 1
    else:
        return 0


# ====================================================================
# Main Monitor Class
# ====================================================================

class DeauthMonitorV2:
    """
    Main WIDS packet handler.

    Integrates Scapy sniffing with all detection methods, database
    persistence, and background housekeeping tasks.
    """

    def __init__(
        self,
        db_host: str = "localhost",
        db_port: int = 3306,
        db_user: str = "root",
        db_password: str = "",
        db_name: str = "wifi_security",
        interface: str = None,
    ):
        """
        Initialize the monitor.

        Args:
            db_host: MySQL host
            db_port: MySQL port
            db_user: MySQL user
            db_password: MySQL password
            db_name: MySQL database name
            interface: Override monitor interface (else from config)
        """
        # --- Database ---
        self.db = WIDSDatabase(
            host=db_host, port=db_port,
            user=db_user, password=db_password,
            database=db_name,
        )

        # --- Config ---
        self.config = ConfigManager(self.db)
        self.config.seed_defaults()
        self._load_config()

        # --- Interface override ---
        if interface:
            self.interface = interface

        # --- AP Baseline ---
        self.ap_baseline = None

        # --- State ---
        self.running = False
        self._bg_thread = None
        self._stats = {
            "packets_total": 0,
            "deauth_detected": 0,
            "attacks_identified": 0,
            "events_inserted": 0,
            "start_time": None,
        }

        logger.info("DeauthMonitorV2 initialized (interface=%s, ap=%s)",
                     self.interface, self.ap_mac)

    def _load_config(self):
        """Load configuration from wids_config table."""
        all_cfg = self.config.get_all()
        self.ap_mac = all_cfg.get("ap_mac", "")
        self.interface = all_cfg.get("monitor_interface", "wlan1mon")
        self.trusted_macs = all_cfg.get("trusted_devices", [])
        self.time_window = all_cfg.get("time_window", 5)
        self.frame_threshold = all_cfg.get("frame_threshold", 30)
        self.level_thresholds = {
            "level1": all_cfg.get("level1_threshold", 40),
            "level2": all_cfg.get("level2_threshold", 60),
            "level3": all_cfg.get("level3_threshold", 85),
            "level4": all_cfg.get("level4_threshold", 95),
        }
        self.level4_enabled = all_cfg.get("level4_enabled", False)
        self.counter_attack_enabled = all_cfg.get("counter_attack_enabled", False)
        self.legal_mode = all_cfg.get("legal_mode", "conservative")

        logger.info("Config loaded: window=%ds, threshold=%d frames, "
                     "levels=%s, legal_mode=%s",
                     self.time_window, self.frame_threshold,
                     self.level_thresholds, self.legal_mode)

    # ================================================================
    # Startup sequence
    # ================================================================

    def start(self):
        """
        Start the WIDS monitor.

        1. Establish AP baseline from beacons
        2. Start background housekeeping thread
        3. Begin Scapy packet capture loop
        """
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is not installed. Cannot start monitor.")
            sys.exit(1)

        self.running = True
        self._stats["start_time"] = time.time()

        # --- Step 1: Establish AP baseline ---
        logger.info("═" * 60)
        logger.info("WIDS Monitor V2 Starting")
        logger.info("═" * 60)

        # Try to load existing baseline from DB first
        existing = self.db.get_baseline(self.ap_mac)
        if existing and existing.get("sample_count", 0) >= 10:
            self.ap_baseline = existing
            logger.info(
                "Loaded existing baseline: mean=%.1f stdev=%.1f (%d samples)",
                existing["rssi_mean"], existing["rssi_stdev"],
                existing["sample_count"],
            )
        else:
            logger.info("Establishing AP baseline (capturing 50 beacons)...")
            self.ap_baseline = establish_ap_baseline(
                ap_mac=self.ap_mac,
                interface=self.interface,
                beacon_count=50,
                timeout=15,
                db=self.db,
            )

        # --- Step 2: Start background thread ---
        self._bg_thread = threading.Thread(
            target=self._background_loop, daemon=True, name="WIDS-BG"
        )
        self._bg_thread.start()
        logger.info("Background housekeeping thread started")

        # --- Step 3: Begin capture ---
        logger.info("Starting packet capture on %s", self.interface)
        logger.info("Monitoring AP: %s", self.ap_mac)
        logger.info("Trusted MACs: %s", self.trusted_macs)
        logger.info("═" * 60)

        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda p: not self.running,
            )
        except KeyboardInterrupt:
            logger.info("Capture interrupted by user")
        except Exception as e:
            logger.error("Capture error: %s", e)
        finally:
            self.stop()

    def stop(self):
        """Stop the monitor gracefully."""
        self.running = False
        logger.info("Monitor stopping...")

        # Final flush
        try:
            flush_fingerprints_to_db(self.db)
        except Exception as e:
            logger.error("Final fingerprint flush failed: %s", e)

        # Print stats
        elapsed = time.time() - (self._stats["start_time"] or time.time())
        logger.info("═" * 60)
        logger.info("WIDS Session Summary")
        logger.info("  Runtime:           %.0f seconds", elapsed)
        logger.info("  Packets processed: %d", self._stats["packets_total"])
        logger.info("  Deauths detected:  %d", self._stats["deauth_detected"])
        logger.info("  Attacks identified:%d", self._stats["attacks_identified"])
        logger.info("  Events inserted:   %d", self._stats["events_inserted"])
        logger.info("  Tracking stats:    %s", get_tracking_stats())
        logger.info("═" * 60)

    # ================================================================
    # Per-packet handler
    # ================================================================

    def _packet_handler(self, pkt):
        """
        Process every captured packet.

        1. Track all packets via continuous_mac_tracking
        2. If deauth/disassoc: run the full detection pipeline
        """
        if not pkt.haslayer(Dot11):
            return

        self._stats["packets_total"] += 1

        # Extract common fields
        src_mac = pkt[Dot11].addr2
        if not src_mac:
            return

        rssi = _extract_rssi(pkt)
        frame_type = _classify_frame_type(pkt)
        now = time.time()

        # Extract sequence number
        seq_num = None
        try:
            sc = pkt[Dot11].SC
            if sc is not None:
                seq_num = sc >> 4  # Upper 12 bits
        except (AttributeError, TypeError):
            pass

        # --- Step 1: Track every packet ---
        continuous_mac_tracking(
            timestamp=now,
            src_mac=src_mac,
            rssi=rssi,
            frame_type=frame_type,
            seq_num=seq_num,
        )

        # --- Step 2: If deauth/disassoc, run detection ---
        if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            self._handle_deauth(pkt, src_mac, rssi, frame_type, seq_num, now)

    def _handle_deauth(
        self, pkt, src_mac: str, rssi, frame_type: str,
        seq_num: int, now: float
    ):
        """Full detection pipeline for a deauth/disassoc frame."""
        self._stats["deauth_detected"] += 1

        dst_mac = pkt[Dot11].addr1 or "ff:ff:ff:ff:ff:ff"
        bssid = pkt[Dot11].addr3 or src_mac

        # Extract reason code
        reason_code = None
        if pkt.haslayer(Dot11Deauth):
            try:
                reason_code = pkt[Dot11Deauth].reason
            except AttributeError:
                pass
        elif pkt.haslayer(Dot11Disas):
            try:
                reason_code = pkt[Dot11Disas].reason
            except AttributeError:
                pass

        # Extract channel
        channel = None
        try:
            if pkt.haslayer(RadioTap):
                channel = getattr(pkt[RadioTap], "ChannelFrequency", None)
                if channel and channel > 2000:
                    # Convert frequency to channel number
                    if 2412 <= channel <= 2484:
                        channel = (channel - 2407) // 5
                    elif 5170 <= channel <= 5825:
                        channel = (channel - 5000) // 5
                    else:
                        channel = None
        except (AttributeError, TypeError):
            pass

        # --- Detection checks ---

        # Check 1: Sequence gap analysis
        gap = detect_sequence_gap(src_mac=src_mac, seq_num=seq_num)

        # Check 2: Temporal mismatch
        temporal = detect_temporal_mismatch(
            src_mac=src_mac,
            current_state=frame_type,
            current_time=now,
        )

        # Check 3: RSSI fingerprinting (fast, always runs)
        rssi_mac, rssi_conf, is_spoofed = detect_by_rssi_fingerprinting(
            deauth_rssi=rssi,
            ap_baseline=self.ap_baseline,
            deauth_time=now,
        )

        # Check 4: Sliding window frame count
        _record_deauth_frame(src_mac)
        frame_count = _count_frames_in_window(src_mac, self.time_window)

        # Check 5: RSSI deviation
        rssi_deviation = None
        if rssi is not None and self.ap_baseline:
            rssi_deviation = abs(rssi - self.ap_baseline.get("rssi_mean", -50))

        # Check 6: Multi-method voting (skip beacon trap for speed)
        attacker_mac, attacker_conf, methods_str = identify_attacker_voting_system(
            deauth_rssi=rssi,
            attack_time=now,
            ap_baseline=self.ap_baseline,
            trusted_macs=self.trusted_macs,
            run_beacon_trap=False,  # Too slow for per-packet
        )

        # --- Compute final confidence ---
        # Start with voting confidence, boost with additional signals
        final_confidence = attacker_conf

        if is_spoofed:
            final_confidence = max(final_confidence, rssi_conf)

        if temporal:
            final_confidence = min(100, final_confidence + 15)
            if "TEMPORAL" not in (methods_str or ""):
                methods_str = (methods_str or "") + "+TEMPORAL"

        if gap is not None and gap > 100:
            final_confidence = min(100, final_confidence + 10)
            if "SEQ_GAP" not in (methods_str or ""):
                methods_str = (methods_str or "") + "+SEQ_GAP"

        if frame_count >= self.frame_threshold:
            # High frame count is itself a strong signal
            rate_boost = min(20, (frame_count - self.frame_threshold) // 5 * 5)
            final_confidence = min(100, max(final_confidence, 50) + rate_boost)
            if "RATE" not in (methods_str or ""):
                methods_str = (methods_str or "") + "+RATE"

        # Clean up methods string
        if methods_str:
            methods_str = methods_str.strip("+")
        else:
            methods_str = "UNKNOWN"

        # --- Prevention level ---
        prevention_level = _calculate_prevention_level(
            final_confidence, self.level_thresholds
        )

        # Cap at level 3 if level 4 is disabled
        if prevention_level >= 4 and not self.level4_enabled:
            prevention_level = 3

        # --- Build event dict ---
        event = {
            "timestamp": datetime.now(),
            "bssid": bssid.upper(),
            "source_mac": src_mac.upper(),
            "victim_mac": dst_mac.upper() if dst_mac != "ff:ff:ff:ff:ff:ff" else None,
            "channel": channel,
            "reason_code": reason_code,
            "frame_count": frame_count,
            "max_rssi": rssi,
            "is_spoofed": is_spoofed,
            "rssi_deviation": rssi_deviation,
            "real_attacker_mac": attacker_mac,
            "attacker_confidence": final_confidence,
            "detection_methods": methods_str,
            "sequence_gap": gap,
            "iat_analysis": None,  # populated by IAT analyzer externally
            "prevention_level": prevention_level,
            "is_active": True,
        }

        # --- Persist to database ---
        try:
            event_id = self.db.insert_event(event)
            self._stats["events_inserted"] += 1
            if attacker_mac:
                self._stats["attacks_identified"] += 1
        except Exception as e:
            logger.error("Failed to insert event: %s", e)
            event_id = None

        # --- Log detection ---
        if final_confidence >= self.level_thresholds.get("level1", 40):
            logger.warning(
                "🚨 DEAUTH ATTACK: src=%s victim=%s bssid=%s "
                "frames=%d conf=%.0f%% level=%d attacker=%s methods=%s",
                src_mac, dst_mac, bssid, frame_count,
                final_confidence, prevention_level,
                attacker_mac or "?", methods_str,
            )
        else:
            logger.debug(
                "deauth: src=%s victim=%s frames=%d conf=%.0f%%",
                src_mac, dst_mac, frame_count, final_confidence,
            )

        return {
            "event_id": event_id,
            "source_mac": src_mac,
            "victim_mac": dst_mac,
            "bssid": bssid,
            "frame_count": frame_count,
            "is_spoofed": is_spoofed,
            "rssi_deviation": rssi_deviation,
            "real_attacker_mac": attacker_mac,
            "attacker_confidence": final_confidence,
            "detection_methods": methods_str,
            "sequence_gap": gap,
            "temporal_mismatch": temporal,
            "prevention_level": prevention_level,
        }

    # ================================================================
    # Background housekeeping
    # ================================================================

    def _background_loop(self):
        """
        Background thread running every 10 seconds:
        1. Expire events older than 60 seconds
        2. Cleanup expired blocks
        3. Flush fingerprints to database
        """
        while self.running:
            try:
                time.sleep(10)
                if not self.running:
                    break

                # 1. Expire old events
                expired = self.db.expire_old_events(max_age_seconds=60)

                # 2. Cleanup expired blocks
                cleaned = self.db.cleanup_expired_blocks()

                # 3. Flush fingerprints
                flushed = flush_fingerprints_to_db(self.db)

                if expired > 0 or cleaned > 0 or flushed > 0:
                    logger.debug(
                        "BG: expired=%d events, cleaned=%d blocks, flushed=%d fps",
                        expired, cleaned, flushed,
                    )

            except Exception as e:
                logger.error("Background task error: %s", e)


# ====================================================================
# CLI entry point
# ====================================================================

def main():
    """Parse CLI args and start the monitor."""
    parser = argparse.ArgumentParser(
        description="WIDS Deauth Monitor V2 — Research-backed attack detection"
    )
    parser.add_argument(
        "--interface", "-i", default=None,
        help="Monitor mode interface (default: from config)"
    )
    parser.add_argument(
        "--db-host", default="localhost",
        help="MySQL host (default: localhost)"
    )
    parser.add_argument(
        "--db-port", type=int, default=3306,
        help="MySQL port (default: 3306)"
    )
    parser.add_argument(
        "--db-user", default="root",
        help="MySQL user (default: root)"
    )
    parser.add_argument(
        "--db-password", default="",
        help="MySQL password (default: empty)"
    )
    parser.add_argument(
        "--db-name", default="wifi_security",
        help="MySQL database (default: wifi_security)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Handle graceful shutdown
    monitor = DeauthMonitorV2(
        db_host=args.db_host,
        db_port=args.db_port,
        db_user=args.db_user,
        db_password=args.db_password,
        db_name=args.db_name,
        interface=args.interface,
    )

    def sighandler(sig, frame):
        logger.info("Signal %d received, stopping...", sig)
        monitor.stop()

    signal.signal(signal.SIGINT, sighandler)
    signal.signal(signal.SIGTERM, sighandler)

    monitor.start()


if __name__ == "__main__":
    main()
