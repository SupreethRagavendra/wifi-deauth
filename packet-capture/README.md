# Packet Capture Engine - Module 2

Real-time Wi-Fi deauthentication frame capture and forwarding.

## Prerequisites
- Linux (Ubuntu/Kali)
- Python 3.10+
- Wireless card with monitor mode support
- Root access

## Installation

### 1. Install system dependencies
```bash
sudo apt update
sudo apt install -y wireless-tools iw python3-pip
```

### 2. Install Python dependencies
```bash
pip3 install -r requirements.txt
```

### 3. Configure
Edit `.env` file:
```
WIFI_INTERFACE=wlan0  # Your wireless interface
WIFI_CHANNEL=6        # Channel to monitor
BACKEND_URL=http://localhost:8080
```

## Usage

### Start capture engine
```bash
sudo python3 main.py
```

### Stop capture
Press `Ctrl+C`

## Testing

### Check if monitor mode works
```bash
sudo iwconfig
# Should show: Mode:Monitor
```

### Test with fake deauth
```bash
# Terminal 1: Run capture engine
sudo python3 main.py

# Terminal 2: Generate test deauth (requires aireplay-ng)
sudo aireplay-ng --deauth 10 -a <AP_MAC> wlan0
```

## Output Example
```
Deauth: AA:BB:CC:DD:EE:FF → 11:22:33:44:55:66 (RSSI: -47 dBm, Seq Gap: 18)
✓ Sent 100 packets to backend
```

## Troubleshooting

**Error: Must run as root**
→ Use `sudo python3 main.py`

**Error: Interface not found**
→ Check `iwconfig` for your interface name
→ Update `WIFI_INTERFACE` in .env

**Error: Failed to enable monitor mode**
→ Kill processes using the interface: `sudo airmon-ng check kill`
→ Try rebooting
