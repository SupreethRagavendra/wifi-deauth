#!/usr/bin/env bash
# start_prevention_properly.sh — Robust prevention engine startup
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "════════════════════════════════════════════════════════════"
echo "  STARTING PREVENTION ENGINE"
echo "════════════════════════════════════════════════════════════"

# Kill old instance
if lsof -Pi :5002 -sTCP:LISTEN -t &>/dev/null; then
    echo -e "${YELLOW}⚠ Engine already running on port 5002. Killing...${NC}"
    kill "$(lsof -t -i:5002)" 2>/dev/null || true
    sleep 2
fi

# Check Python deps
echo "Checking Python dependencies..."
MISSING=()
python3 -c "import flask" 2>/dev/null       || MISSING+=("flask flask-cors")
python3 -c "import requests" 2>/dev/null     || MISSING+=("requests")
python3 -c "import mysql.connector" 2>/dev/null || MISSING+=("mysql-connector-python")
python3 -c "import yaml" 2>/dev/null         || MISSING+=("pyyaml")
python3 -c "import reportlab" 2>/dev/null    || MISSING+=("reportlab")
python3 -c "import dpkt" 2>/dev/null         || MISSING+=("dpkt")

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo -e "${YELLOW}Installing missing deps: ${MISSING[*]}${NC}"
    pip3 install "${MISSING[@]}" >/dev/null 2>&1
fi
echo -e "${GREEN}✓${NC} All dependencies satisfied"

# Create dirs
mkdir -p "$ROOT/prevention-engine/logs"
chmod 755 "$ROOT/prevention-engine/logs"

# Check backend is reachable (warn only)
if ! curl -sf http://localhost:8080/actuator/health -o /dev/null 2>/dev/null; then
    echo -e "${YELLOW}⚠ Backend (port 8080) does not appear reachable.${NC}"
    echo "  Engine will start but polling will fail until backend is up."
fi

# Start engine with sudo
echo ""
echo "Starting prevention engine (requires sudo)..."
cd "$ROOT"
sudo python3 prevention-engine/level1.py &
ENGINE_PID=$!
echo "PID: $ENGINE_PID"

# Wait for health check
echo "Waiting for engine to come up..."
for i in $(seq 1 10); do
    sleep 1
    if curl -sf http://localhost:5002/health -o /dev/null 2>/dev/null; then
        break
    fi
    echo "  Waiting... ($i/10)"
done

# Verify
if curl -sf http://localhost:5002/health -o /dev/null 2>/dev/null; then
    echo -e "\n${GREEN}✓ Prevention engine is running and healthy!${NC}"
    echo ""
    curl -s http://localhost:5002/health | python3 -m json.tool 2>/dev/null || true
    echo ""
    echo "Monitor logs:  tail -f prevention-engine/logs/engine.log"
    echo "Dashboard:     http://localhost:3000/prevention"
else
    echo -e "\n${RED}✗ Engine failed to start.${NC}"
    echo "Check logs: cat prevention-engine/logs/engine.log"
    if [[ -f "prevention-engine/logs/startup.log" ]]; then
        echo "Startup log:"
        cat prevention-engine/logs/startup.log
    fi
    exit 1
fi

echo ""
echo "════════════════════════════════════════════════════════════"
