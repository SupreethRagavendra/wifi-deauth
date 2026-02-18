#!/bin/bash

# Setup environment for WiFi Security Platform

echo "📦 Installing Dependencies..."

# 1. System Dependencies
sudo apt update
sudo apt install -y default-jdk maven nodejs npm python3 python3-pip aircrack-ng wireless-tools net-tools

# 2. Python Dependencies
pip3 install -r packet-capture/requirements.txt --break-system-packages

# 3. Backend Setup
echo "🧹 Cleaning Backend..."
cd wifi-security-backend
./mvnw clean install -DskipTests
cd ..

# 4. Frontend Setup
echo "🧹 Cleaning Frontend..."
cd wifi-security-frontend
npm install
cd ..

echo "✅ Setup Complete!"
echo "Run ./start_realtime_system.sh to launch."
