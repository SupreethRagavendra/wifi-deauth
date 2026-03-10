#!/bin/bash
# 🛡️ Radio Readiness & Auto-Repair Script
# Ensures wlan0 is Managed (Client) and wlan1 is Monitor (Sniffer)
# Clears hardware blocks and forces reconnection.

STATION="wlan0"
MONITOR="wlan1"
LOG="/tmp/radio_ready.log"

echo "[$(date)] 🚀 Starting Radio Readiness Sequence..." | tee -a $LOG

# 1. Clear Software/Hardware Locks
echo "🔓 Clearing RFKILL blocks..."
sudo rfkill unblock wifi
sudo rfkill unblock all

# 2. Reset WiFi Stack
echo "🔄 Restarting NetworkManager..."
sudo systemctl restart NetworkManager
sleep 2

# 3. Configure STATION (wlan0)
echo "📶 Configuring $STATION (Client Mode)..."
sudo nmcli device set $STATION managed yes
sudo nmcli radio wifi on
sudo ip link set $STATION up

# 4. Configure MONITOR (wlan1)
echo "📡 Configuring $MONITOR (Monitor Mode)..."
sudo nmcli device set $MONITOR managed no
sudo ip link set $MONITOR down
sudo iw dev $MONITOR set type monitor
sudo ip link set $MONITOR up

# 5. Force High-Speed Reconnection for STATION
echo "🔗 Brute-forcing connection for $STATION..."
# Try to connect to the most recent/best connection
sudo nmcli device connect $STATION

# Final Status Check
echo "✅ Readiness Check Completed." | tee -a $LOG
nmcli device status | tee -a $LOG
echo "--------------------------------" | tee -a $LOG
