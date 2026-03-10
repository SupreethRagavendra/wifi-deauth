"""
prevention-engine/level2_components.py
Level 2: Application Resilience (fires at >= 60% confidence, additive to L1)

Components:
  2A: TCP Connection Preservation
  2B: Application Session Persistence (MPTCP)
  2C: Smart Buffering
  2D: Intelligent Download Manager
"""

import subprocess
import os
import logging

INTERFACE = os.getenv("WIFI_INTERFACE", "wlan1")
MIN_CONFIDENCE_L2 = float(os.getenv("MIN_CONFIDENCE_L2", "60"))

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
logger = logging.getLogger("components")
if not logger.handlers:
    fh = logging.FileHandler(os.path.join(LOG_DIR, "components.log"))
    fh.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
    logger.addHandler(fh)


def _sysctl(params: dict):
    applied = []
    for key, val in params.items():
        try:
            subprocess.run(["sudo", "sysctl", "-w", f"{key}={val}"],
                           capture_output=True, text=True, timeout=2)
            applied.append(key)
        except Exception:
            pass
    return applied


class Component2A:
    id    = "2A"
    label = "TCP Connection Preservation"
    TCP_PARAMS = {
        "net.ipv4.tcp_keepalive_time": "30", "net.ipv4.tcp_keepalive_intvl": "5",
        "net.ipv4.tcp_keepalive_probes": "3", "net.ipv4.tcp_retries2": "8",
        "net.ipv4.tcp_fastopen": "3", "net.ipv4.tcp_syn_retries": "3",
        "net.ipv4.tcp_fin_timeout": "15",
    }
    def apply(self, event: dict) -> dict:
        applied = _sysctl(self.TCP_PARAMS)
        detail = f"L2A: TCP optimized for resilience ({len(applied)}/{len(self.TCP_PARAMS)} params)"
        logger.info(detail)
        return {"ok": True, "detail": detail}


class Component2B:
    id    = "2B"
    label = "Application Session Persistence (MPTCP)"
    def apply(self, event: dict) -> dict:
        try:
            result = subprocess.run(["sudo", "sysctl", "-w", "net.mptcp.mptcp_enabled=1"],
                                    capture_output=True, text=True, timeout=2)
            detail = "L2B: MPTCP enabled" if result.returncode == 0 else "L2B: MPTCP unavailable (kernel support missing)"
        except Exception:
            detail = "L2B: MPTCP unavailable (kernel support missing)"
        logger.info(detail)
        return {"ok": True, "detail": detail}


class Component2C:
    id    = "2C"
    label = "Smart Buffering"
    BUFFER_PARAMS = {
        "net.core.rmem_max": "134217728", "net.core.wmem_max": "134217728",
        "net.core.rmem_default": "1048576", "net.core.wmem_default": "1048576",
        "net.ipv4.tcp_rmem": "4096 1048576 134217728", "net.ipv4.tcp_wmem": "4096 1048576 134217728",
        "net.ipv4.tcp_max_syn_backlog": "16384", "net.ipv4.tcp_window_scaling": "1",
    }
    def apply(self, event: dict) -> dict:
        applied = _sysctl(self.BUFFER_PARAMS)
        detail = f"L2C: Network buffers increased ({len(applied)}/{len(self.BUFFER_PARAMS)} params)"
        logger.info(detail)
        return {"ok": True, "detail": detail}


class Component2D:
    id    = "2D"
    label = "Intelligent Download Manager"
    ARIA2_CONF = "continue=true\nmax-connection-per-server=4\nmin-split-size=1M\nsplit=4\nmax-concurrent-downloads=5\nretry-wait=2\nmax-tries=0\ntimeout=10\nconnect-timeout=5\n"
    WGETRC = "tries=0\nretry-connrefused=on\nwaitretry=2\ntimeout=10\ncontinue=on\n"
    def apply(self, event: dict) -> dict:
        results = []
        aria2_dir = os.path.expanduser("~/.aria2")
        os.makedirs(aria2_dir, exist_ok=True)
        try:
            with open(os.path.join(aria2_dir, "aria2.conf"), "w") as f:
                f.write(self.ARIA2_CONF)
            results.append("aria2: configured")
        except Exception as e:
            results.append(f"aria2 err: {e}")
        try:
            with open(os.path.expanduser("~/.wgetrc"), "w") as f:
                f.write(self.WGETRC)
            results.append("wget: configured")
        except Exception as e:
            results.append(f"wget err: {e}")
        detail = f"L2D: Download manager configured — {' | '.join(results)}"
        logger.info(detail)
        return {"ok": True, "detail": detail}


ALL_L2_COMPONENTS = [Component2A(), Component2B(), Component2C(), Component2D()]

def get_l2_components():
    return ALL_L2_COMPONENTS

def should_apply_l2(confidence: float) -> bool:
    return confidence >= MIN_CONFIDENCE_L2
