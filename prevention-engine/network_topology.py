"""
prevention-engine/network_topology.py
Dynamically discovers registered WiFi networks and their connected clients
from the Spring Boot backend (/api/wifi and /api/wifi/{id}/clients).

Uses credentials from config.yml. Refreshes every 60 seconds in background.
"""

import os
import threading
import time
import requests
import yaml

# ── Config ──
_CFG_PATH = os.path.join(os.path.dirname(__file__), "config.yml")

def _load_config():
    try:
        with open(_CFG_PATH) as f:
            return yaml.safe_load(f)
    except Exception:
        return {}

_cfg = _load_config()
_net = _cfg.get("network", {})

BACKEND_URL      = _cfg.get("backend", {}).get("url", "http://localhost:8080")
ADMIN_EMAIL      = os.getenv("ADMIN_EMAIL",      "supreethvennila@gmail.com")
ADMIN_PASSWORD   = os.getenv("ADMIN_PASSWORD",   "Supreeth24")
REFRESH_INTERVAL = int(os.getenv("TOPOLOGY_REFRESH_INTERVAL", "60"))


class NetworkTopology:
    def __init__(self):
        self.protected_bssids  = set()
        self.protected_clients = set()
        self._bssid_to_info    = {}
        self._bssid_to_clients = {}
        self._jwt              = None
        self._running          = False

    def _login(self):
        try:
            r = requests.post(f"{BACKEND_URL}/api/auth/login", json={
                "email": ADMIN_EMAIL, "password": ADMIN_PASSWORD,
            }, timeout=5)
            if r.status_code == 200:
                data = r.json()
                self._jwt = data.get("token") or data.get("jwt")
        except Exception:
            pass

    def _headers(self):
        return {"Authorization": f"Bearer {self._jwt}"} if self._jwt else {}

    def _fetch_networks(self):
        try:
            r = requests.get(f"{BACKEND_URL}/api/wifi", headers=self._headers(), timeout=5)
            if r.status_code == 200:
                return r.json() if isinstance(r.json(), list) else r.json().get("data", [])
            elif r.status_code == 401:
                self._login()
                r = requests.get(f"{BACKEND_URL}/api/wifi", headers=self._headers(), timeout=5)
                if r.status_code == 200:
                    return r.json() if isinstance(r.json(), list) else r.json().get("data", [])
        except Exception:
            pass
        return []

    def _fetch_clients(self, wifi_id: str):
        try:
            r = requests.get(f"{BACKEND_URL}/api/wifi/{wifi_id}/clients",
                             headers=self._headers(), timeout=5)
            if r.status_code == 200:
                data = r.json()
                clients_list = data if isinstance(data, list) else data.get("data", [])
                return [(c.get("macAddress") or c.get("mac_address") or c.get("mac", "")).lower()
                        for c in clients_list if c.get("macAddress") or c.get("mac_address") or c.get("mac")]
        except Exception:
            pass
        return []

    def refresh(self):
        networks = self._fetch_networks()
        new_bssids, new_clients, new_info, new_b2c = set(), set(), {}, {}
        for net in networks:
            bssid = (net.get("bssid") or net.get("macAddress") or "").lower()
            if not bssid:
                continue
            new_bssids.add(bssid)
            wifi_id = net.get("id") or net.get("wifiId")
            new_info[bssid] = {"ssid": net.get("ssid") or "", "channel": net.get("channel") or 0, "wifi_id": wifi_id}
            if wifi_id:
                clients = self._fetch_clients(str(wifi_id))
                new_b2c[bssid] = set(clients)
                new_clients.update(clients)
        self.protected_bssids, self.protected_clients = new_bssids, new_clients
        self._bssid_to_info, self._bssid_to_clients = new_info, new_b2c
        if new_bssids:
            print(f"  [Topology] {len(new_bssids)} APs, {len(new_clients)} clients loaded")

    def event_is_relevant(self, attacker_mac: str, target_mac: str) -> bool:
        a, t = (attacker_mac or "").lower(), (target_mac or "").lower()
        return t in self.protected_clients or t in self.protected_bssids or a in self.protected_bssids

    def get_victim_clients(self, attacker_mac: str, target_mac: str) -> list:
        t, a = (target_mac or "").lower(), (attacker_mac or "").lower()
        if t in self.protected_clients:
            return [t]
        if a in self.protected_bssids:
            clients = self._bssid_to_clients.get(a, set())
            return list(clients) if clients else [t]
        return [t] if t else []

    def channel_for_bssid(self, bssid: str):
        return self._bssid_to_info.get(bssid.lower(), {}).get("channel", 0)

    def ssid_for_bssid(self, bssid: str):
        return self._bssid_to_info.get(bssid.lower(), {}).get("ssid", "")

    def start_background_refresh(self):
        if self._running:
            return
        self._running = True
        self.refresh()
        def _loop():
            while self._running:
                time.sleep(REFRESH_INTERVAL)
                try:
                    self.refresh()
                except Exception as e:
                    print(f"  [Topology] Refresh error: {e}")
        threading.Thread(target=_loop, daemon=True).start()

    def stop(self):
        self._running = False


topology = NetworkTopology()
