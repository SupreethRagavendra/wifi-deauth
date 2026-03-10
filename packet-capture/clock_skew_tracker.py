"""
Clock Skew Tracker — Physical Layer Fingerprinting (Layer 3)

Every wireless device has a slightly different clock crystal oscillation.
By measuring the timestamp field in beacon/probe frames over time, we can
compute a unique "clock skew" (drift in ppm) for each device.

KEY INSIGHT: An attacker spoofing the AP's MAC cannot spoof the AP's clock
crystal. The real AP drifts at, say, +2.3 ppm. The attacker's hardware
drifts at, say, -1.7 ppm. This difference is detectable and unforgeable.

Requirements: Only 1 sensor (wlan1 monitor mode) ✅
Accuracy: Can distinguish devices within ~0.5 ppm difference

Output: clock_skew_ppm (float) + is_impersonation (bool) + confidence (0-15)
"""

import time
import logging
import statistics
from collections import defaultdict, deque
from typing import Optional, Dict, Tuple

logger = logging.getLogger("ClockSkewTracker")


class ClockSkewTracker:
    """
    Tracks per-device clock skew using beacon/probe response timestamps.
    Detects MAC impersonation by comparing clock skew of incoming frames
    against the known skew of the claimed device.
    """

    def __init__(self, min_samples: int = 10, tolerance_ppm: float = 1.0):
        """
        min_samples:   minimum timestamp pairs needed to compute skew
        tolerance_ppm: how much skew difference (in ppm) before flagging
        """
        self._observations: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=200)
        )
        self._known_skews: Dict[str, dict] = {}  # mac → {skew_ppm, stdev, count}
        self._min_samples = min_samples
        self._tolerance_ppm = tolerance_ppm

    def record_timestamp(self, mac: str, frame_timestamp: int, local_timestamp: float = None):
        """
        Record a beacon/probe timestamp for clock skew analysis.

        Args:
            mac:             Source MAC of the beacon/probe frame
            frame_timestamp: The TSF (Timing Synchronization Function) from the frame
                            This is the 802.11 microsecond timestamp
            local_timestamp: Our local monotonic time when we received the frame
                            (defaults to time.monotonic())
        """
        if mac is None or frame_timestamp is None:
            return

        mac = mac.upper()
        local_ts = local_timestamp if local_timestamp is not None else time.monotonic()

        self._observations[mac].append((local_ts, frame_timestamp))

        # Auto-compute skew once we have enough data
        obs = self._observations[mac]
        if len(obs) >= self._min_samples:
            self._compute_skew(mac, obs)

    def _compute_skew(self, mac: str, observations: deque):
        """
        Compute clock skew using linear regression on (local_time, frame_timestamp) pairs.
        
        The slope of the linear fit gives the clock's tick rate.
        Deviation from 1.0 (in ppm) is the clock skew.
        """
        if len(observations) < 2:
            return

        # Use the first observation as reference
        ref_local, ref_frame = observations[0]

        # Compute offsets (to avoid large number arithmetic issues)
        offsets = []
        for local_ts, frame_ts in observations:
            dt_local = local_ts - ref_local  # seconds
            dt_frame = (frame_ts - ref_frame) / 1e6  # microseconds → seconds
            if dt_local > 0.1:  # need at least 100ms separation
                offsets.append((dt_local, dt_frame))

        if len(offsets) < 3:
            return

        # Simple linear fit: dt_frame = slope * dt_local + intercept
        # slope should be ~1.0 for a perfect clock
        # skew_ppm = (slope - 1.0) * 1e6
        n = len(offsets)
        sum_x = sum(o[0] for o in offsets)
        sum_y = sum(o[1] for o in offsets)
        sum_xx = sum(o[0] ** 2 for o in offsets)
        sum_xy = sum(o[0] * o[1] for o in offsets)

        denom = n * sum_xx - sum_x ** 2
        if abs(denom) < 1e-12:
            return

        slope = (n * sum_xy - sum_x * sum_y) / denom
        skew_ppm = (slope - 1.0) * 1e6

        # Compute residuals for stdev (quality of linear fit)
        intercept = (sum_y - slope * sum_x) / n
        residuals = []
        for x, y in offsets:
            predicted = slope * x + intercept
            residuals.append(abs(y - predicted) * 1e6)  # in microseconds

        fit_stdev = statistics.stdev(residuals) if len(residuals) > 1 else 999.0

        self._known_skews[mac] = {
            'skew_ppm': round(skew_ppm, 3),
            'stdev_us': round(fit_stdev, 2),
            'count': len(offsets),
            'last_updated': time.time(),
        }

    def get_skew(self, mac: str) -> Optional[dict]:
        """Get the clock skew for a known device."""
        return self._known_skews.get(mac.upper())

    def is_impersonation(self, claimed_mac: str, frame_timestamp: int,
                         local_timestamp: float = None) -> Tuple[bool, int, str]:
        """
        Check if a frame claiming to be from claimed_mac has a consistent clock skew.

        Returns:
            (is_impersonation, score_0_to_15, reason)
        """
        claimed_mac = claimed_mac.upper()
        local_ts = local_timestamp if local_timestamp is not None else time.monotonic()

        known = self._known_skews.get(claimed_mac)
        if known is None or known['count'] < self._min_samples:
            return False, 0, "insufficient_data"

        # Get the expected skew for this MAC
        expected_skew = known['skew_ppm']

        # Compute instantaneous skew from this single frame vs recent history
        obs = self._observations.get(claimed_mac)
        if obs is None or len(obs) < 2:
            return False, 0, "no_recent_data"

        # Compare this frame's timestamp progression to the known skew
        ref_local, ref_frame = obs[-1]  # Most recent known frame
        dt_local = local_ts - ref_local
        if dt_local < 0.01:  # Too close together to measure
            return False, 0, "too_close"

        dt_frame = (frame_timestamp - ref_frame) / 1e6
        instant_slope = dt_frame / dt_local if dt_local > 0 else 1.0
        instant_skew = (instant_slope - 1.0) * 1e6

        skew_diff = abs(instant_skew - expected_skew)

        if skew_diff > self._tolerance_ppm * 5:
            # Very large skew difference — strong impersonation signal
            score = 15
            return True, score, f"skew_diff={skew_diff:.1f}ppm"
        elif skew_diff > self._tolerance_ppm * 3:
            score = 10
            return True, score, f"skew_diff={skew_diff:.1f}ppm"
        elif skew_diff > self._tolerance_ppm:
            score = 5
            return True, score, f"skew_diff={skew_diff:.1f}ppm"
        else:
            return False, 0, f"consistent_skew={instant_skew:.1f}ppm"

    def get_all_skews(self) -> dict:
        """Return all known device clock skews."""
        return dict(self._known_skews)

    def get_device_count(self) -> int:
        """How many devices have established clock skew profiles."""
        return len(self._known_skews)
