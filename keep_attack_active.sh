#!/bin/bash

# Continuous attack simulator to keep status UNSAFE
# This sends packets every 5 seconds to maintain the attack status

echo "🔴 Starting continuous attack simulation..."
echo "This will keep the dashboard status as UNSAFE"
echo "Press Ctrl+C to stop"
echo ""

while true; do
    echo "[$(date +%H:%M:%S)] Sending attack burst..."
    
    # Send 10 packets rapidly
    for i in {1..10}; do
        curl -s -X POST http://localhost:8080/api/packets/deauth/batch \
            -H "Content-Type: application/json" \
            -d "{\"packets\":[{\"sourceMac\":\"94:65:2D:97:25:87\",\"destMac\":\"9E:A8:2C:C2:1F:D9\",\"bssid\":\"9E:A8:2C:C2:1F:D9\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\",\"channel\":1,\"signal\":-45,\"reasonCode\":7}]}" \
            > /dev/null
        sleep 0.1
    done
    
    # Check status
    STATUS=$(curl -s http://localhost:8080/api/detection/status | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    echo "   Status: $STATUS"
    
    # Wait 5 seconds before next burst (keeps within 30s cooldown)
    sleep 5
done
