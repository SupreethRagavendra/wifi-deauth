import os
import sys
import yaml
import requests

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "config.yml")
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
        
    backend_url = config.get("backend", {}).get("url", "http://localhost:8080")
    
    # Try fetching dynamic interface based on UI settings
    try:
        res = requests.get(f"{backend_url}/api/system/adapter", timeout=2)
        if res.status_code == 200:
            adapter = res.json().get("adapter", "wlan1")
            config.setdefault("network", {})["interface"] = adapter
    except Exception:
        pass # fallback to whatever is in config.yml
        
    return config

