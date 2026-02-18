#!/bin/bash

# Configuration
INTERFACE="wlan1"
MONITOR_INTERFACE="wlan1"

echo "Running interface setup for $INTERFACE..."

# Check if interface exists
if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
    echo "Error: Interface $INTERFACE not found."
    exit 1
fi

# Check if already in monitor mode
CURRENT_MODE=$(iwconfig "$INTERFACE" 2>/dev/null | grep Mode | awk '{print $4}' | cut -d: -f2)

if [ "$CURRENT_MODE" == "Monitor" ]; then
    echo "Interface $INTERFACE is already in Monitor mode."
else
    echo "Putting interface $INTERFACE into Monitor mode..."
    sudo ip link set "$INTERFACE" down
    sudo iw dev "$INTERFACE" set type monitor
    sudo ip link set "$INTERFACE" up
    echo "Done."
fi

# Verify
FINAL_MODE=$(iwconfig "$INTERFACE" 2>/dev/null | grep Mode | awk '{print $4}' | cut -d: -f2)
if [ "$FINAL_MODE" == "Monitor" ]; then
    echo "Success: $INTERFACE is in Monitor mode."
else
    echo "Error: Failed to set $INTERFACE to Monitor mode."
    exit 1
fi
