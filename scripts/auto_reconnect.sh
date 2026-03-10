#!/bin/bash
# auto_reconnect.sh — Instant Wi-Fi Reconnection Script
# Runs on the VICTIM device to instantly reconnect when deauthed.
# Requires root privileges (sudo) to run wpa_cli commands.

IFACE="wlan0"

echo "======================================================="
echo "  🛡️ Wi-Fi Auto-Reconnect Shield"
echo "  Monitoring Interface: $IFACE"
echo "  Press Ctrl+C to stop"
echo "======================================================="

# Check if wpa_cli is available
if ! command -v wpa_cli &> /dev/null; then
    echo "❌ Error: wpa_cli not found! Please install wpasupplicant."
    exit 1
fi

reconnect_count=0

while true; do
    # Get current WPA state
    STATE=$(wpa_cli -i "$IFACE" status 2>/dev/null | grep "^wpa_state=" | cut -d= -f2)

    # Note: If interface is down or wpa_supplicant isn't running, STATE will be empty.
    # We mainly care if it's explicitly NOT "COMPLETED" (and not empty)
    if [[ -n "$STATE" && "$STATE" != "COMPLETED" && "$STATE" != "ASSOCIATING" && "$STATE" != "AUTHENTICATING" && "$STATE" != "4WAY_HANDSHAKE" && "$STATE" != "GROUP_HANDSHAKE" ]]; then
        reconnect_count=$((reconnect_count + 1))
        
        # Get timestamp
        TS=$(date '+%H:%M:%S.%3N')
        echo "[$TS] ⚡ Disconnected! (State: $STATE) Forcing instant reconnect... (#$reconnect_count)"

        # Force reassociate (fastest reconnect method, skips full scan)
        wpa_cli -i "$IFACE" reassociate > /dev/null

        # Give it a moment to try reassociating
        sleep 0.2
        
        # Check if it worked, if not, do a full reconnect
        NEW_STATE=$(wpa_cli -i "$IFACE" status 2>/dev/null | grep "^wpa_state=" | cut -d= -f2)
        if [[ "$NEW_STATE" != "COMPLETED" && "$NEW_STATE" != "ASSOCIATING" && "$NEW_STATE" != "AUTHENTICATING" ]]; then
            echo "[$TS] 🔄 Reassociation failed, trying full reconnect..."
            wpa_cli -i "$IFACE" reconnect > /dev/null
            sleep 0.5
        fi
    fi

    # Poll every 50ms for ultra-fast response
    sleep 0.05
done
