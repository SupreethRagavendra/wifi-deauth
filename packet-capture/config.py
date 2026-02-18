import os
import sys
from dotenv import load_dotenv

# Add the project root to sys.path to ensure local imports work correctly
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

load_dotenv()

class Config:
    """Centralized configuration for the Packet Capture Engine"""
    
    # Wireless interface
    INTERFACE = os.getenv('WIFI_INTERFACE', 'wlan1')
    
    # Backend API
    BACKEND_URL = os.getenv('BACKEND_URL', 'http://localhost:8080')
    PACKET_ENDPOINT = f"{BACKEND_URL}/api/packets/deauth/batch"
    DETECTION_ENDPOINT = f"{BACKEND_URL}/api/detection/alert"
    
    # Capture settings
    CHANNEL = int(os.getenv('WIFI_CHANNEL', '1'))  # Default channel 1
    CAPTURE_DURATION = 5  # Seconds per scan cycle
    BUFFER_SIZE = 5  # buffer 5 packets to send in batch - reduced for real-time
    SEND_INTERVAL = 1  # Check every second
    
    # Feature extraction
    DEAUTH_SUBTYPE = 0x0C  # IEEE 802.11 deauth frame subtype
    
    # Retry settings
    MAX_RETRIES = 3
    RETRY_DELAY = 2  # seconds
