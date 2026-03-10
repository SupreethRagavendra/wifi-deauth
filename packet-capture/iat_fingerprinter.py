"""
IAT (Frame Inter-Arrival Time) Fingerprinter
=============================================
Uses timing gaps between consecutive frames to identify the ATTACK TOOL,
not just the spoofed MAC address. Each tool has a distinct IAT signature.

Based on research: "Analyzing the temporal characteristics and timing disparities
using the Radiotap header, you can fingerprint the attacker based on the
behavioral timing of their specific device or attack script."

Known signatures (empirical averages):
  aireplay-ng --deauth: ~0.8ms (very regular, hardware-timed)
  mdk4 a/d mode:       ~0.2ms (very fast, burst bursts)
  scapy custom:        ~2-5ms (Python overhead)
  legitimate mgmt:     >50ms  (normal AP management traffic)
"""

import time
import logging
import statistics
from collections import deque

logger = logging.getLogger("IAT_Fingerprinter")

# Known tooling signatures (min_iat_ms, max_iat_ms, tool_name)
TOOL_SIGNATURES = [
    (0.05, 0.5,  "mdk4"),
    (0.5,  2.0,  "aireplay-ng"),
    (2.0,  8.0,  "scapy_script"),
    (8.0,  50.0, "custom_tool"),
]

class IATFingerprinter:
    def __init__(self, window_size=50):
        """
        window_size: number of frames to track per source MAC
        """
        self._arrival_times = {}  # mac -> deque of timestamps
        self._window = window_size

    def record_frame(self, src_mac: str):
        """Record the arrival time of a frame from a given source MAC."""
        now = time.perf_counter()  # High-resolution timer
        if src_mac not in self._arrival_times:
            self._arrival_times[src_mac] = deque(maxlen=self._window)
        self._arrival_times[src_mac].append(now)

    def analyze(self, src_mac: str) -> dict:
        """
        Compute IAT stats for a MAC and fingerprint the likely attack tool.
        Returns a dict with: iat_ms, iat_stdev_ms, attacker_tool, confidence
        """
        times = self._arrival_times.get(src_mac)
        
        if not times or len(times) < 5:
            return {
                "iat_ms": None,
                "iat_stdev_ms": None,
                "attacker_tool": "unknown",
                "iat_confidence": 0
            }

        # Compute inter-arrival times in milliseconds
        iats = [(times[i] - times[i-1]) * 1000 for i in range(1, len(times))]
        
        if not iats:
            return {"iat_ms": None, "iat_stdev_ms": None, "attacker_tool": "unknown", "iat_confidence": 0}

        mean_iat = statistics.mean(iats)
        stdev_iat = statistics.stdev(iats) if len(iats) > 1 else 0

        # Match against known tool signatures
        tool = "unknown"
        confidence = 0
        for (min_ms, max_ms, tool_name) in TOOL_SIGNATURES:
            if min_ms <= mean_iat < max_ms:
                tool = tool_name
                # Confidence: how "clean" and regular the timing is
                # Lower stdev relative to mean = more regular = more confident
                if stdev_iat < mean_iat * 0.5:
                    confidence = 90
                elif stdev_iat < mean_iat:
                    confidence = 70
                else:
                    confidence = 50
                break

        if mean_iat > 50:
            tool = "legitimate_traffic"
            confidence = 80

        return {
            "iat_ms": round(mean_iat, 3),
            "iat_stdev_ms": round(stdev_iat, 3),
            "attacker_tool": tool,
            "iat_confidence": confidence
        }

    def is_attack_pattern(self, src_mac: str) -> bool:
        """Returns True if the IAT pattern matches a known attack tool."""
        result = self.analyze(src_mac)
        return result.get("attacker_tool") not in ("unknown", "legitimate_traffic")

    def get_summary(self, src_mac: str) -> str:
        """Human readable summary for logging."""
        r = self.analyze(src_mac)
        if r["iat_ms"] is None:
            return "IAT: insufficient data"
        return (
            f"IAT: {r['iat_ms']:.2f}ms ±{r['iat_stdev_ms']:.2f}ms | "
            f"Tool: {r['attacker_tool']} ({r['iat_confidence']}% conf)"
        )
