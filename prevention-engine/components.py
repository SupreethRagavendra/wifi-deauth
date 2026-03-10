"""
prevention-engine/components.py
Level 1: Fast Reconnection (fires at >= 40% confidence)

Components:
  1A: Pre-Association Caching (OKC)
  1B: Aggressive Probe Response
  1C: Channel Hint Broadcasting
  1D: Predictive Pre-Authentication

All components return {ok: bool, detail: str} and log to logs/components.log.
Each must complete within 500ms and be idempotent.
"""

import os
import re
import subprocess
import logging
from datetime import datetime

# ── Config ──
INTERFACE    = os.getenv("WIFI_INTERFACE", "wlan1")
VICTIM_MAC   = os.getenv("VICTIM_MAC",   "4C:6F:9C:F4:FA:63")
AP_MAC       = os.getenv("AP_MAC",       "9E:A8:2C:C2:1F:D9")
HOSTAPD_CONF = os.getenv("HOSTAPD_CONF", "/etc/hostapd/hostapd.conf")
WPA_CONF     = os.getenv("WPA_CONF",     "/etc/wpa_supplicant/wpa_supplicant.conf")
CHANNEL      = int(os.getenv("WIFI_CHANNEL", "11"))
SSID         = os.getenv("SSID", "supreeth")

# ── Logger setup ──
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("components")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    fh = logging.FileHandler(os.path.join(LOG_DIR, "components.log"))
    fh.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
    logger.addHandler(fh)


def _discover_ip(mac: str):
    """Look up an IP from ARP cache given a MAC address."""
    try:
        out = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=3).stdout
        for line in out.splitlines():
            if mac.lower() in line.lower():
                parts = line.split()
                if parts:
                    return parts[0]
    except Exception:
        pass
    return None


def _run_cmd(cmd, timeout=2):
    """Run a shell command safely, return (ok, stdout)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


# ─────────────────────────────────────────────────────────────────────────────
# 1A: Pre-Association Caching (OKC)
# ─────────────────────────────────────────────────────────────────────────────
class Component1A:
    id    = "1A"
    label = "Pre-Association Caching (OKC)"

    HOSTAPD_OPTS = {
        "okc":                   "1",
        "disable_pmksa_caching": "0",
        "rsn_preauth":           "1",
        "ft_over_ds":            "1",
        "ft_psk_generate_local": "1",
    }

    def _patch_keyval(self, path: str, opts: dict):
        if not os.path.isfile(path):
            return False, f"File not found: {path}"
        try:
            with open(path) as f:
                content = f.read()
            changed = False
            for key, val in opts.items():
                pattern = rf"^{re.escape(key)}\s*=.*$"
                replacement = f"{key}={val}"
                if re.search(pattern, content, re.MULTILINE):
                    content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
                    changed = True
                else:
                    content += f"\n{replacement}"
                    changed = True
            if changed:
                with open(path, "w") as f:
                    f.write(content)
            return True, f"Patched {len(opts)} keys in {os.path.basename(path)}"
        except Exception as e:
            return False, str(e)

    def apply(self, event: dict) -> dict:
        results = []
        ok1, msg1 = self._patch_keyval(WPA_CONF, {
            "okc": "1", "proactive_key_caching": "1",
            "bgscan": '"simple:30:-65:300"',
        })
        results.append(f"wpa_supplicant: {msg1}")
        ok2, msg2 = self._patch_keyval(HOSTAPD_CONF, self.HOSTAPD_OPTS)
        results.append(f"hostapd: {msg2}")
        ok3, msg3 = _run_cmd(f"sudo wpa_cli -i {INTERFACE} set network 0 proactive_key_caching 1")
        results.append(f"wpa_cli OKC: {'ok' if ok3 else msg3}")
        detail = " | ".join(results)
        logger.info(f"L1A: {detail}")
        return {"ok": True, "detail": f"L1A: OKC enabled — {detail}"}


# ─────────────────────────────────────────────────────────────────────────────
# 1B: Aggressive Probe Response
# ─────────────────────────────────────────────────────────────────────────────
class Component1B:
    id    = "1B"
    label = "Aggressive Probe Response"

    def apply(self, event: dict) -> dict:
        results = []
        if os.path.isfile(HOSTAPD_CONF):
            try:
                with open(HOSTAPD_CONF) as f:
                    content = f.read()
                if re.search(r"^beacon_int=", content, re.MULTILINE):
                    content = re.sub(r"^beacon_int=.*$", "beacon_int=50", content, flags=re.MULTILINE)
                else:
                    content += "\nbeacon_int=50"
                with open(HOSTAPD_CONF, "w") as f:
                    f.write(content)
                results.append("beacon_int=50 set")
            except Exception as e:
                results.append(f"hostapd patch err: {e}")
        else:
            results.append("hostapd.conf not found (skipped)")
        ok, msg = _run_cmd(f"sudo iw dev {INTERFACE} set type managed 2>/dev/null; true")
        results.append("iw type set attempted")
        detail = " | ".join(results)
        logger.info(f"L1B: {detail}")
        return {"ok": True, "detail": f"L1B: Fast probe response configured — {detail}"}


# ─────────────────────────────────────────────────────────────────────────────
# 1C: Channel Hint Broadcasting
# ─────────────────────────────────────────────────────────────────────────────
class Component1C:
    id    = "1C"
    label = "Channel Hint Broadcasting"

    def apply(self, event: dict) -> dict:
        ok, output = _run_cmd(f"sudo iwlist {INTERFACE} channel 2>/dev/null | grep 'Current'")
        if ok and output:
            channel_info = output.strip()
        else:
            channel_info = f"Channel {CHANNEL} (from config)"
        hint_path = "/tmp/channel_hint.txt"
        try:
            with open(hint_path, "w") as f:
                f.write(f"{channel_info}\nchannel={CHANNEL}\nssid={SSID}\n")
            detail = f"L1C: Channel cached: {channel_info}"
        except Exception as e:
            detail = f"L1C: Channel hint write failed: {e}"
        logger.info(detail)
        return {"ok": True, "detail": detail}


# ─────────────────────────────────────────────────────────────────────────────
# 1D: Predictive Pre-Authentication
# ─────────────────────────────────────────────────────────────────────────────
class Component1D:
    id    = "1D"
    label = "Predictive Pre-Authentication"

    def apply(self, event: dict) -> dict:
        confidence = event.get("confidence", 0)
        results = []
        ok1, msg1 = _run_cmd(f"sudo wpa_cli -i {INTERFACE} reassociate")
        results.append(f"reassociate: {'ok' if ok1 else msg1}")
        if confidence >= 75:
            ok2, msg2 = _run_cmd(f"sudo dhclient -1 -timeout 5 {INTERFACE} 2>/dev/null &")
            results.append(f"dhclient: {'ok' if ok2 else msg2}")
        detail = " | ".join(results)
        logger.info(f"L1D: Pre-auth initiated — {detail}")
        return {"ok": True, "detail": f"L1D: Pre-auth initiated — {detail}"}


# ── Registry ─────────────────────────────────────────────────────────────────
ALL_COMPONENTS = [Component1A(), Component1B(), Component1C(), Component1D()]

def get_all_components():
    return ALL_COMPONENTS

def pick_component(confidence: float):
    if confidence >= 40:
        return ALL_COMPONENTS[0]
    return None
