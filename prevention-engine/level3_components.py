"""
prevention-engine/level3_components.py
Level 3: UX Optimization (fires at >= 85% confidence, additive to L1+L2)

Components:
  3A: Perceptual Masking
  3B: Notification Suppression
  3C: Seamless Handoff Illusion
  3D: Progressive Degradation
"""

import os
import subprocess
import logging

INTERFACE = os.getenv("WIFI_INTERFACE", "wlan1")
SSID      = os.getenv("SSID", "supreeth")
MIN_CONFIDENCE_L3 = float(os.getenv("MIN_CONFIDENCE_L3", "85"))

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
logger = logging.getLogger("components")
if not logger.handlers:
    fh = logging.FileHandler(os.path.join(LOG_DIR, "components.log"))
    fh.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
    logger.addHandler(fh)

def _run_cmd(cmd, timeout=2):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


class Component3A:
    id    = "3A"
    label = "Perceptual Masking"
    def apply(self, event: dict) -> dict:
        results = []
        ok, _ = _run_cmd("gsettings set org.gnome.nm-applet disable-disconnected-notifications true 2>/dev/null")
        results.append(f"gnome-nm: {'suppressed' if ok else 'not available'}")
        ok2, _ = _run_cmd("gsettings set org.gnome.desktop.notifications show-banners false 2>/dev/null")
        results.append(f"banners: {'hidden' if ok2 else 'skipped'}")
        detail = f"L3A: Notifications masked — {' | '.join(results)}"
        logger.info(detail)
        return {"ok": True, "detail": detail}


class Component3B:
    id    = "3B"
    label = "Notification Suppression"
    def apply(self, event: dict) -> dict:
        results = []
        ok, _ = _run_cmd(f"nmcli connection modify {SSID} connection.wait-device-timeout 5000 2>/dev/null")
        results.append(f"wait-timeout: {'5s' if ok else 'skipped'}")
        ok2, _ = _run_cmd(f"nmcli connection modify {SSID} connection.auth-retries 5 2>/dev/null")
        results.append(f"auth-retries: {'5' if ok2 else 'skipped'}")
        detail = f"L3B: Notification delay set to 5s — {' | '.join(results)}"
        logger.info(detail)
        return {"ok": True, "detail": detail}


class Component3C:
    id    = "3C"
    label = "Seamless Handoff Illusion"
    def apply(self, event: dict) -> dict:
        results = []
        ok, _ = _run_cmd(f"sudo iw dev {INTERFACE} set power_save off 2>/dev/null")
        results.append(f"power_save: {'off' if ok else 'skipped'}")
        ok2, _ = _run_cmd(f"sudo iw dev {INTERFACE} set frag 2346 2>/dev/null")
        results.append(f"frag: {'set' if ok2 else 'skipped'}")
        detail = f"L3C: Power save disabled for fast handoff — {' | '.join(results)}"
        logger.info(detail)
        return {"ok": True, "detail": detail}


class Component3D:
    id    = "3D"
    label = "Progressive Degradation"
    def apply(self, event: dict) -> dict:
        conf_path = "/tmp/quality_ladder.conf"
        try:
            with open(conf_path, "w") as f:
                f.write("# Progressive Degradation — Quality Ladder\n")
                f.write("quality_levels=[1080p,720p,480p,audio-only]\n")
                f.write("fallback_timeout_ms=2000\nrecovery_timeout_ms=5000\nmin_bandwidth_kbps=128\n")
            detail = f"L3D: Quality ladder configured → {conf_path}"
        except Exception as e:
            detail = f"L3D: Quality ladder write failed: {e}"
        logger.info(detail)
        return {"ok": True, "detail": detail}


ALL_L3_COMPONENTS = [Component3A(), Component3B(), Component3C(), Component3D()]

def get_l3_components():
    return ALL_L3_COMPONENTS

def should_apply_l3(confidence: float) -> bool:
    return confidence >= MIN_CONFIDENCE_L3
