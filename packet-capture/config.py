import os
import sys
import requests
from dotenv import load_dotenv

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
load_dotenv()

class Config:
    """Centralized configuration for the Packet Capture Engine"""
    
    # Backend API
    BACKEND_URL = os.getenv('BACKEND_URL', 'http://localhost:8080')
    PACKET_ENDPOINT = f"{BACKEND_URL}/api/packets/deauth/batch"
    DETECTION_ENDPOINT = f"{BACKEND_URL}/api/detection/alert"
    
    # Fetch wireless interface from backend system settings (or fallback to wlan1)
    try:
        res = requests.get(f"{BACKEND_URL}/api/system/adapter", timeout=2)
        if res.status_code == 200:
            INTERFACE = res.json().get("adapter", "wlan1")
        else:
            INTERFACE = os.getenv('WIFI_INTERFACE', 'wlan1')
    except Exception:
        INTERFACE = os.getenv('WIFI_INTERFACE', 'wlan1')
    
    # Capture settings
    CHANNEL = int(os.getenv('WIFI_CHANNEL', '11'))  # Default channel 11
    CAPTURE_DURATION = 5  # Seconds per scan cycle
    BUFFER_SIZE = 5    # flush every 5 packets (was 50 — way too slow for real-time)
    SEND_INTERVAL = 0.15 # flush every 150ms for near-instant delivery
    
    # Feature extraction
    DEAUTH_SUBTYPE = 0x0C  # IEEE 802.11 deauth frame subtype
    
    # Retry settings
    MAX_RETRIES = 3
    RETRY_DELAY = 0.5  # seconds
