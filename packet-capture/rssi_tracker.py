"""
RSSI-Based Deauthentication Attack Detector (Layer 3)

APPROACH: Detect the ATTACK, not the ATTACKER.

An attacker can change their MAC in 1 second. They CANNOT change:
  - Their physical location (RSSI signature)
  - The fact that they must send deauth frames
  - The timing pattern of their hardware
  - The rate of their attack

This module uses:
  1. AP Baseline RSSI — detect deviations from known AP location
  2. RSSISignatureMatcher — per-device fingerprinting (FINALPROMPT spec)
     Learns RSSI of every device, detects MAC spoofing when RSSI mismatches
  3. Rate-based detection — flood rate analysis

Output: attack_confirmed (bool) + attack_confidence (0-100) + score_boost
"""

import time
import json
import os
import logging
import statistics
from collections import defaultdict, deque
from typing import Optional, Dict, List

logger = logging.getLogger("RSSITracker")


# ═════════════════════════════════════════════════════════════════════════════
# RSSI SIGNATURE MATCHER — Per-device RSSI fingerprinting (single sensor)
# From FINALPROMPT.md: Learns RSSI "fingerprint" of every device seen.
# When attack starts: compare attack frame RSSI to all known devices.
# ═════════════════════════════════════════════════════════════════════════════

class RSSISignatureMatcher:
    """
    Matches RSSI to known device signatures.
    Detects: AP impersonation, client spoofing.
    Works with single sensor.
    """

    def __init__(self, tolerance_db=8):
        self.signatures = {}       # mac → rssi_signature
        self.tolerance = tolerance_db
        self._learning_buffer = defaultdict(list)  # mac → [rssi, rssi, ...]
        self._min_samples = 5      # need at least 5 frames to learn a device
        self._max_buffer = 100     # keep last 100 samples for rolling update

    def record_rssi(self, mac: str, rssi: int):
        """
        Record an RSSI observation for a device during normal operation.
        Automatically learns/updates the signature once enough samples exist.
        """
        if rssi is None:
            return
        mac = mac.upper()
        buf = self._learning_buffer[mac]
        buf.append(rssi)
        # Keep rolling window
        if len(buf) > self._max_buffer:
            buf.pop(0)
        # Auto-learn once we have enough samples
        if len(buf) >= self._min_samples:
            self._update_signature(mac, buf)

    def _update_signature(self, mac: str, rssi_list: list):
        """Update the RSSI signature of a device."""
        self.signatures[mac] = {
            'mean':  statistics.mean(rssi_list),
            'std':   statistics.stdev(rssi_list) if len(rssi_list) > 1 else 0,
            'min':   min(rssi_list),
            'max':   max(rssi_list),
            'count': len(rssi_list)
        }

    def learn_device(self, mac: str, rssi_list: list):
        """Manually learn the RSSI signature of a device (batch)."""
        if not rssi_list:
            return
        mac = mac.upper()
        self.signatures[mac] = {
            'mean':  statistics.mean(rssi_list),
            'std':   statistics.stdev(rssi_list) if len(rssi_list) > 1 else 0,
            'min':   min(rssi_list),
            'max':   max(rssi_list),
            'count': len(rssi_list)
        }

    def check_frame(self, claimed_mac: str, observed_rssi: int):
        """
        Frame claims to be from claimed_mac.
        Does the RSSI match what we know about that MAC?

        Returns:
            'match'    → RSSI consistent with known device
            'mismatch' → RSSI very different → possible spoofing
            'unknown'  → never seen this MAC before
        """
        claimed_mac = claimed_mac.upper()
        if claimed_mac not in self.signatures:
            return 'unknown', 0

        sig = self.signatures[claimed_mac]
        expected = sig['mean']
        deviation = abs(observed_rssi - expected)

        if deviation <= self.tolerance:
            return 'match', deviation
        else:
            return 'mismatch', deviation   # Likely spoofed frame

    def mismatch_score(self, claimed_mac: str, observed_rssi: int) -> int:
        """Returns 0-20 score. Higher = more likely spoofed."""
        result, deviation = self.check_frame(claimed_mac, observed_rssi)

        if result == 'unknown':
            return 10   # Unknown device is somewhat suspicious
        elif result == 'mismatch':
            if deviation > 25:
                return 20
            elif deviation > 15:
                return 15
            else:
                return 8
        else:
            return 0    # Match = legitimate

    def get_known_devices(self) -> dict:
        """Return all known device signatures."""
        return dict(self.signatures)


class RSSITracker:
    def __init__(self, config_path: str = None):
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "..", "config", "network_config.json"
            )
        self.config = self._load_config(config_path)

        self.target_ap_mac = self.config["target_ap_mac"].upper()
        self.trusted_macs = set(
            m.upper() for m in self.config.get("trusted_device_macs", [])
        )
        self.trusted_macs.add(self.target_ap_mac)

        # Auto-trust AP MAC variants (bit-flip variants like 9E→9F)
        self._ap_mac_bytes = self._mac_to_bytes(self.target_ap_mac)
        ap_variants = self._generate_ap_variants(self.target_ap_mac)
        self.trusted_macs.update(ap_variants)

        # Tuning parameters
        self.beacon_target = self.config.get("baseline_beacon_count", 50)
        self.baseline_timeout = self.config.get("baseline_timeout_seconds", 30)
        self.min_sigma = self.config.get("rssi_min_sigma", 6)

        # ══ Phase 1: AP Baseline ════════════════════════════════════════
        self.baseline: Dict[str, float] = {}
        self.baseline_samples: List[int] = []
        self.baseline_ready = False

        # ══ RSSI Signature Matcher (per-device fingerprinting) ═══════════
        self.sig_matcher = RSSISignatureMatcher(tolerance_db=8)

        # ══ Attack Tracking ═════════════════════════════════════════════
        self.deauth_timestamps: deque = deque(maxlen=1000)
        self.deauth_sources: Dict[str, int] = defaultdict(int)  # src → count
        self.deauth_victims: set = set()
        self.spoofed_count = 0
        self.total_deauths = 0

        # Rolling attack rate (frames per second)
        self._rate_window = deque(maxlen=100)

    @staticmethod
    def _load_config(path: str) -> dict:
        if not os.path.exists(path):
            logger.warning(f"Config not found at {path}, creating default")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            default = {
                "target_ap_mac": "FF:FF:FF:FF:FF:FF",
                "trusted_device_macs": [],
                "wifi_channel": 1,
                "monitor_interface": "wlan1mon",
            }
            with open(path, "w") as f:
                json.dump(default, f, indent=2)
            return default

        with open(path) as f:
            cfg = json.load(f)
        logger.info(f"Loaded config: AP={cfg['target_ap_mac']}, "
                     f"trusted={cfg.get('trusted_device_macs', [])}")
        return cfg

    # ═════════════════════════════════════════════════════════════════════
    # MAC UTILITIES
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def _mac_to_bytes(mac: str) -> list:
        try:
            return [int(b, 16) for b in mac.split(":")]
        except (ValueError, AttributeError):
            return [0] * 6

    @staticmethod
    def _bytes_to_mac(b: list) -> str:
        return ":".join(f"{x:02X}" for x in b)

    def _generate_ap_variants(self, ap_mac: str) -> set:
        """Generate MAC variants that are likely the same AP.
        APs often use multiple BSSIDs differing by 1-2 bits."""
        variants = set()
        ap_bytes = self._mac_to_bytes(ap_mac)
        if ap_bytes == [0] * 6:
            return variants

        # Flip bits 0, 1, both in first byte
        for bit_mask in [0x01, 0x02, 0x03]:
            v = list(ap_bytes)
            v[0] = ap_bytes[0] ^ bit_mask
            variants.add(self._bytes_to_mac(v))

        # Last-byte offsets (multi-BSSID)
        for offset in range(1, 5):
            v = list(ap_bytes)
            v[5] = (ap_bytes[5] + offset) & 0xFF
            variants.add(self._bytes_to_mac(v))
            v[5] = (ap_bytes[5] - offset) & 0xFF
            variants.add(self._bytes_to_mac(v))

        variants.discard(ap_mac.upper())
        return variants

    def _is_ap_variant(self, mac: str) -> bool:
        """Check if MAC differs from AP by ≤2 bits."""
        mac_bytes = self._mac_to_bytes(mac)
        diff_bits = 0
        for a, b in zip(self._ap_mac_bytes, mac_bytes):
            diff_bits += bin(a ^ b).count('1')
        return diff_bits <= 2

    # ═════════════════════════════════════════════════════════════════════
    # PHASE 1: ESTABLISH AP BASELINE
    # ═════════════════════════════════════════════════════════════════════

    def record_beacon(self, bssid: str, rssi) -> bool:
        """Record beacon RSSI from target AP. Returns True when baseline ready."""
        if self.baseline_ready:
            return True
        if not bssid or bssid.upper() != self.target_ap_mac:
            return False
        if rssi is None:
            return False

        rssi = int(rssi)

        # ── Filter out locally-injected frames looping back through wlan1 ──
        # Our defense injects beacons and auth frames with AP BSSID as SA.
        # wlan1 (monitor) receives its own TX at 0-distance RSSI (~-5 to -20 dBm).
        # Real AP at 1-5m is -30 to -50 dBm. Anything louder than -25 dBm is
        # our own injected frame — exclude it from the baseline.
        MIN_REAL_BEACON_RSSI = -25  # dBm  (real AP must be quieter than this)
        if rssi > MIN_REAL_BEACON_RSSI:
            return False  # skip — this is a loopback injection artifact

        self.baseline_samples.append(rssi)
        count = len(self.baseline_samples)
        if count % 10 == 0:
            logger.info(f"[BASELINE] Beacons: {count}/{self.beacon_target}")
        if count >= self.beacon_target:
            self._finalize_baseline()
            return True
        return False

    def _finalize_baseline(self):
        samples = self.baseline_samples
        self.baseline = {
            "mean": statistics.mean(samples),
            "stdev": statistics.stdev(samples) if len(samples) > 1 else 3.0,
            "min": min(samples),
            "max": max(samples),
            "count": len(samples),
        }
        self.baseline_ready = True
        logger.info(
            f"[BASELINE] ✅ mean={self.baseline['mean']:.1f}dBm "
            f"stdev={self.baseline['stdev']:.1f}dB n={self.baseline['count']}"
        )

    def force_baseline(self, mean: float, stdev: float = 3.0):
        """Manually set baseline (used when no beacons received)."""
        self.baseline = {
            "mean": mean, "stdev": stdev,
            "min": mean - 10, "max": mean + 5, "count": 0,
        }
        self.baseline_ready = True

    # ═════════════════════════════════════════════════════════════════════
    # PHASE 2: FRAME RECORDING (for attack rate tracking)
    # ═════════════════════════════════════════════════════════════════════

    def record_frame(self, src_mac: str, rssi, frame_type: str):
        """Record any frame. Used for attack rate + RSSI signature learning."""
        if src_mac is None:
            return
        mac = src_mac.upper()

        # Auto-trust AP variants seen in the wild
        if mac not in self.trusted_macs and self._is_ap_variant(mac):
            self.trusted_macs.add(mac)
            logger.info(f"[AUTO-TRUST] {mac} is AP variant")

        # ── RSSI Signature Learning ─────────────────────────────────────
        # Learn the RSSI fingerprint of every device during normal frames
        # (beacons, probes, data). This builds the per-device baseline.
        if rssi is not None and frame_type not in ("deauth", "disassoc"):
            self.sig_matcher.record_rssi(mac, int(rssi))

    # ═════════════════════════════════════════════════════════════════════
    # PHASE 3: ATTACK DETECTION (the core)
    # ═════════════════════════════════════════════════════════════════════

    def analyze_deauth(self, src_mac: str, dst_mac: str, bssid: str,
                       rssi) -> dict:
        """
        Analyze a deauth frame. Detects the ATTACK, not the attacker.

        Returns:
          attack_confirmed  — True if this is definitely a spoofed attack
          attack_confidence — 0-100 how sure we are it's spoofed
          score_boost       — how much to boost the backend's threat score
          detection_method  — what evidence confirmed it
          attack_rate       — deauth frames per second (rolling)
          rssi_deviation    — how far from AP baseline (0 if no RSSI)
        """
        now = time.time()
        self.total_deauths += 1
        self._rate_window.append(now)
        self.deauth_timestamps.append(now)

        src_upper = src_mac.upper() if src_mac else ""
        dst_upper = dst_mac.upper() if dst_mac else ""
        self.deauth_sources[src_upper] = self.deauth_sources.get(src_upper, 0) + 1

        # Track victims (the real clients being disconnected)
        if dst_upper and dst_upper != "FF:FF:FF:FF:FF:FF":
            self.deauth_victims.add(dst_upper)

        # Calculate rolling attack rate
        attack_rate = self._calc_attack_rate()

        # ── RSSI Signature Mismatch Check ─────────────────────────────
        sig_mismatch_score = 0
        sig_result = 'n/a'
        if rssi is not None and src_upper:
            sig_result, sig_dev = self.sig_matcher.check_frame(src_upper, int(rssi))
            sig_mismatch_score = self.sig_matcher.mismatch_score(src_upper, int(rssi))

        result = {
            "attack_confirmed": False,
            "attack_confidence": 0,
            "detection_method": "NONE",
            "score_boost": 0,
            "rssi_deviation": 0.0,
            "ap_baseline_rssi": self.baseline.get("mean", 0.0),
            "attack_rate": round(attack_rate, 1),
            "total_deauths": self.total_deauths,
            "unique_victims": len(self.deauth_victims),
            "spoofed_sources": len(
                [s for s in self.deauth_sources if s in self.trusted_macs]
            ),
            # RSSI Signature Matching results
            "rssi_sig_result": sig_result,
            "rssi_sig_mismatch_score": sig_mismatch_score,
            # Keep these for backward compatibility
            "is_spoofed": False,
            "real_attacker_mac": None,
            "attacker_confidence": 0,
        }

        is_ap_spoofed = (src_upper == self.target_ap_mac or
                         src_upper in self.trusted_macs and
                         self._is_ap_variant(src_upper))
        is_client_spoofed = (src_upper in self.trusted_macs and
                             not is_ap_spoofed and
                             src_upper != self.target_ap_mac)

        # If source is AP or AP variant, check RSSI before flagging
        # If RSSI matches baseline, this is a LEGITIMATE deauth from the AP
        if is_ap_spoofed and rssi is not None and self.baseline_ready:
            deviation = abs(int(rssi) - self.baseline["mean"])
            threshold = max(self.baseline["stdev"] * 3, self.min_sigma)
            if deviation <= threshold:
                # RSSI matches AP — legitimate deauth, not an attack
                return result

        # ── CASE 1: Unknown source sending deauth ─────────────────────
        # Non-trusted MAC openly sending deauth = definite attack evidence
        if not is_ap_spoofed and not is_client_spoofed:
            if src_upper not in self.trusted_macs:
                if self._is_ap_variant(src_upper):
                    self.trusted_macs.add(src_upper)
                    return result

                result["attack_confirmed"] = True
                result["is_spoofed"] = True
                result["attack_confidence"] = 90
                result["detection_method"] = "UNKNOWN_SOURCE_DEAUTH"
                result["score_boost"] = 70
                self.spoofed_count += 1

                logger.warning(
                    f"[ATTACK] 🚨 Unknown source deauth: {src_upper} → {dst_mac} "
                    f"rate={attack_rate:.1f}/s"
                )
            return result

        # ── CASE 2: Trusted MAC sending deauth (likely spoofed) ───────
        # Someone is sending deauth frames CLAIMING to be the AP or a client.
        # This is the core attack scenario.

        # Sub-case: No baseline, but trusted source sending deauth is suspicious
        if not self.baseline_ready:
            result["attack_confirmed"] = True
            result["is_spoofed"] = True
            result["detection_method"] = "NO_BASELINE_TRUSTED_DEAUTH"
            result["attack_confidence"] = _rate_confidence(attack_rate)
            result["score_boost"] = _rate_boost(attack_rate)
            self.spoofed_count += 1
            return result

        # Sub-case: No RSSI — can't do RSSI check, but rate-based detection
        if rssi is None:
            result["attack_confirmed"] = True
            result["is_spoofed"] = True
            result["detection_method"] = "NO_RSSI"
            result["attack_confidence"] = _rate_confidence(attack_rate)
            result["score_boost"] = _rate_boost(attack_rate)
            self.spoofed_count += 1
            return result

        # Sub-case: RSSI available — do physics-based detection
        rssi = int(rssi)
        baseline_mean = self.baseline["mean"]
        baseline_stdev = self.baseline["stdev"]
        deviation = abs(rssi - baseline_mean)
        threshold = max(baseline_stdev * 3, self.min_sigma)

        result["rssi_deviation"] = round(deviation, 1)

        if deviation > threshold:
            # ═══ CONFIRMED SPOOFED ATTACK (physics-based proof) ════════
            result["attack_confirmed"] = True
            result["is_spoofed"] = True
            result["detection_method"] = "RSSI_DEVIATION"

            # Confidence based on RSSI deviation + rate + signature mismatch
            rssi_conf = min(95, 50 + int(deviation * 3))
            rate_conf = _rate_confidence(attack_rate)
            # Boost confidence if signature also mismatches
            sig_bonus = sig_mismatch_score * 2  # Up to +40
            result["attack_confidence"] = min(99, max(rssi_conf, rate_conf) + sig_bonus)

            # Score boost: Instant escalation to Level 4 (95) on confirmed physics-based spoofing
            result["score_boost"] = 95
            self.spoofed_count += 1

            logger.warning(
                f"[ATTACK] 🚨 RSSI CONFIRMED: rssi={rssi}dBm "
                f"baseline={baseline_mean:.1f}dBm "
                f"dev={deviation:.1f}dB > thresh={threshold:.1f}dB "
                f"rate={attack_rate:.1f}/s conf={result['attack_confidence']}% "
                f"sig={sig_result}(+{sig_mismatch_score})"
            )
        elif sig_mismatch_score >= 15:
            # ═══ RSSI matches baseline but SIGNATURE says this MAC was never here ════
            # Attacker is at same distance as AP but device fingerprint doesn't match
            result["attack_confirmed"] = True
            result["is_spoofed"] = True
            result["detection_method"] = "RSSI_SIG_MISMATCH"
            result["attack_confidence"] = min(90, 60 + sig_mismatch_score)
            result["score_boost"] = 60 + sig_mismatch_score
            self.spoofed_count += 1
            logger.warning(
                f"[ATTACK] 🚨 RSSI SIG MISMATCH: {src_upper} sig={sig_result} "
                f"mismatch_score={sig_mismatch_score} rate={attack_rate:.1f}/s"
            )
        else:
            # RSSI matches baseline — could be legitimate deauth from AP
            # But if the rate is suspiciously high, still flag it
            if attack_rate > 2:
                result["attack_confirmed"] = True
                result["is_spoofed"] = True
                result["detection_method"] = "HIGH_RATE"
                result["attack_confidence"] = _rate_confidence(attack_rate)
                result["score_boost"] = _rate_boost(attack_rate)
                self.spoofed_count += 1

        return result

    def _calc_attack_rate(self) -> float:
        """Calculate deauth frames per second over the last 5 seconds."""
        now = time.time()
        window = 5.0
        recent = [t for t in self._rate_window if now - t <= window]
        if len(recent) < 2:
            return 0.0
        duration = recent[-1] - recent[0]
        if duration <= 0:
            return float(len(recent))
        return len(recent) / duration

    def get_status(self) -> dict:
        return {
            "baseline_ready": self.baseline_ready,
            "baseline": self.baseline,
            "total_deauths": self.total_deauths,
            "spoofed_count": self.spoofed_count,
            "attack_rate": round(self._calc_attack_rate(), 1),
            "unique_victims": len(self.deauth_victims),
            "spoofed_sources": self.deauth_sources,
        }


# ═════════════════════════════════════════════════════════════════════════
# RATE-BASED CONFIDENCE (attack rate → confidence/boost)
# ═════════════════════════════════════════════════════════════════════════
# Normal: 0-2 deauth/s (AP management)
# Suspicious: 3-10/s (possible attack)
# Definite attack: 10+/s (flood)

def _rate_confidence(rate: float) -> int:
    """Convert deauth rate to confidence percentage."""
    if rate >= 20:
        return 95
    elif rate >= 10:
        return 85
    elif rate >= 5:
        return 75
    elif rate >= 2:
        return 60
    else:
        return 40

def _rate_boost(rate: float) -> int:
    """Convert deauth rate to score boost."""
    if rate >= 20:
        return 70     # Level 3+ guaranteed
    elif rate >= 10:
        return 60     # Level 3
    elif rate >= 5:
        return 50     # Level 2+
    elif rate >= 2:
        return 40     # Level 2
    else:
        return 25     # Level 1
