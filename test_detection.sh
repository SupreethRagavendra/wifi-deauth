#!/bin/bash

# ===================================
# WiFi Deauth Detection - Full Test Script
# ===================================

set -e

echo "🚀 Starting WiFi Deauth Detection System Test"
echo "=============================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Kill any existing backend processes
echo -e "\n${YELLOW}Step 1: Cleaning up existing processes...${NC}"
lsof -ti:8080 | xargs kill -9 2>/dev/null || true
sleep 2

# Step 2: Start Backend
echo -e "\n${GREEN}Step 2: Starting Backend (MySQL)...${NC}"
cd wifi-security-backend
./mvnw spring-boot:run > /tmp/backend.log 2>&1 &
BACKEND_PID=$!
cd ..

echo "Backend PID: $BACKEND_PID"
echo "Waiting for backend to start..."

# Wait for backend to be ready
for i in {1..30}; do
    if curl -s http://localhost:8080/api/detection/status > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Backend is ready!${NC}"
        break
    fi
    echo -n "."
    sleep 1
done

# Step 3: Verify backend is running
echo -e "\n${YELLOW}Step 3: Verifying backend status...${NC}"
STATUS=$(curl -s http://localhost:8080/api/detection/status)
echo "Current status: $STATUS"

# Step 4: Send test deauth packets
echo -e "\n${YELLOW}Step 4: Sending test deauth packets...${NC}"
echo "Sending 15 packets over 7.5 seconds to trigger detection..."

for i in {1..15}; do
    TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
    curl -s -X POST http://localhost:8080/api/packets/deauth/batch \
        -H "Content-Type: application/json" \
        -d "{\"packets\":[{\"sourceMac\":\"94:65:2D:97:25:87\",\"destMac\":\"9E:A8:2C:C2:1F:D9\",\"bssid\":\"9E:A8:2C:C2:1F:D9\",\"timestamp\":\"$TIMESTAMP\",\"channel\":1,\"signal\":-45,\"reasonCode\":7}]}" \
        > /dev/null
    echo -n "📡 Packet $i sent... "
    sleep 0.5
done

echo -e "\n${GREEN}✅ All packets sent!${NC}"

# Step 5: Check detection status
echo -e "\n${YELLOW}Step 5: Checking detection status...${NC}"
sleep 2
STATUS=$(curl -s http://localhost:8080/api/detection/status)
echo "Status after attack: $STATUS"

# Step 6: Check events
echo -e "\n${YELLOW}Step 6: Checking detection events...${NC}"
EVENTS=$(curl -s http://localhost:8080/api/detection/events/recent)
echo "Events: $EVENTS"

# Step 7: Summary
echo -e "\n${GREEN}=============================================="
echo "✅ Test Complete!"
echo "=============================================="
echo ""
echo "📊 Results:"
echo "  - Backend PID: $BACKEND_PID"
echo "  - Backend logs: /tmp/backend.log"
echo "  - Packets sent: 15"
echo ""
echo "🌐 Access Points:"
echo "  - Backend API: http://localhost:8080"
echo "  - Frontend UI: http://localhost:3000"
echo "  - Detection Monitor: http://localhost:3000/detection-monitor"
echo ""
echo "📝 Next Steps:"
echo "  1. Open http://localhost:3000 in your browser"
echo "  2. Check the Detection Monitor page"
echo "  3. Status should show 'UNSAFE' (RED) if attack detected"
echo "  4. Events should appear in the feed"
echo ""
echo "🛑 To stop backend: kill $BACKEND_PID"
echo "=============================================="
${NC}
