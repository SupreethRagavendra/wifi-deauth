#!/bin/bash

echo "============================================="
echo "   Fixing WiFi Interface & Resetting State"
echo "============================================="

INTERFACE="wlan1"

# 1. Kill conflicting processes
echo "--> Killing conflicting processes..."
sudo killall airodump-ng 2>/dev/null
sudo killall aireplay-ng 2>/dev/null
sudo pkill -f "python3 main.py" 2>/dev/null
sudo pkill -f "python3 scan_clients.py" 2>/dev/null
sudo pkill -f "python3 scan_networks.py" 2>/dev/null

# 2. Reset Interface
echo "--> Resetting $INTERFACE..."
sudo ifconfig $INTERFACE down
sudo iwconfig $INTERFACE mode managed
sudo ifconfig $INTERFACE up
echo "   (Reset to Managed Mode)"

# 3. Clean up temp files
echo "--> Cleaning up temp files..."
sudo rm -f /tmp/scan_clients_* 
sudo rm -f /tmp/scan_networks_*

# 4. Check status
echo "--> Current Status of $INTERFACE:"
iwconfig $INTERFACE

echo "============================================="
echo "   DONE! You can now run 'make run-sniffer'"
echo "============================================="
