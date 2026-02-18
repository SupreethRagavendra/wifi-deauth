#!/bin/bash

# ==========================================
# WiFi Security Platform - Real-time Startup
# ==========================================

echo "🚀 Starting WiFi Security Platform in REAL-TIME mode..."
echo "-----------------------------------------------------"

# 1. Cleanup previous sessions
echo "🧹 Cleaning up previous processes..."
pkill -f "wifi-security-backend"
pkill -f "packet-capture/main.py"
lsof -ti:8080 | xargs kill -9 2>/dev/null
lsof -ti:3000 | xargs kill -9 2>/dev/null

# 2. Start Backend
echo "Backend: Starting..."
cd wifi-security-backend
./mvnw spring-boot:run > ../backend.log 2>&1 &
BACKEND_PID=$!
echo "Backend detected with PID $BACKEND_PID. Waiting for startup..."
cd ..

# Wait for backend to be ready
RETRIES=30
while [ $RETRIES -gt 0 ]; do
    if curl -s http://localhost:8080/actuator/health >/dev/null; then
        echo "✅ Backend is UP!"
        break
    fi
    echo "Waiting for backend... ($RETRIES)"
    sleep 2
    RETRIES=$((RETRIES-1))
done

if [ $RETRIES -eq 0 ]; then
    echo "❌ Backend failed to start. Check backend.log"
    exit 1
fi

# 3. Start Frontend
echo "Frontend: Starting..."
cd wifi-security-frontend
npm run dev > ../frontend.log 2>&1 &
FRONTEND_PID=$!
echo "✅ Frontend started with PID $FRONTEND_PID"
cd ..

# 4. Start Real-time Packet Capture (The Core Requirement)
echo "📡 Packet Capture: Starting on wlan1..."
export WIFI_INTERFACE=wlan1
export BACKEND_URL=http://localhost:8080

# Capture needs sudo. If script run as user, invoke sudo.
if [ "$EUID" -ne 0 ]; then
  echo "⚠️  Asking for sudo to start packet capture engine..."
  sudo -E python3 packet-capture/main.py > capture.log 2>&1 &
else
  python3 packet-capture/main.py > capture.log 2>&1 &
fi
CAPTURE_PID=$!
echo "✅ Packet Capture Engine started with PID $CAPTURE_PID"

echo "-----------------------------------------------------"
echo "🎉 System is LIVE!"
echo "   - Dashboard: http://localhost:3000"
echo "   - Backend API: http://localhost:8080"
echo "   - Monitoring Interface: wlan1"
echo "-----------------------------------------------------"

cleanup() {
    echo "🛑 Stopping all services..."
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    sudo kill $CAPTURE_PID 2>/dev/null
    echo "Done."
    exit
}

trap cleanup SIGINT

# Wait indefinitely
wait
