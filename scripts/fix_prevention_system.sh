#!/usr/bin/env bash
# fix_prevention_system.sh — Master script: diagnose, fix, and verify
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║       PREVENTION SYSTEM — MASTER FIX SCRIPT             ║"
echo "╚══════════════════════════════════════════════════════════╝"

# Step 1: Full diagnostics
echo ""
echo "━━━ Step 1: Running full diagnostics ━━━"
cd "$ROOT"
bash scripts/diagnose_prevention.sh 2>&1 | tee /tmp/prevention_diagnosis.txt

echo ""
echo "━━━ Step 2: Testing detection → backend ━━━"
python3 scripts/fix_detection_to_backend.py

echo ""
echo "━━━ Step 3: Testing backend → prevention engine ━━━"
python3 scripts/fix_backend_to_prevention.py

echo ""
echo "━━━ Step 4: Check if prevention engine needs restart ━━━"
if ! curl -sf http://localhost:5002/health -o /dev/null 2>/dev/null; then
    echo "Prevention engine is DOWN — starting it..."
    bash scripts/start_prevention_properly.sh
else
    echo "Prevention engine already running."
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║               SYSTEM STATUS SUMMARY                     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Quick status check
for svc in "Backend:8080" "ML:5000" "Prevention:5002" "Frontend:3000"; do
    NAME="${svc%%:*}"
    PORT="${svc##*:}"
    if curl -sf "http://localhost:$PORT" -o /dev/null 2>/dev/null || \
       ss -tlnp 2>/dev/null | grep -q ":$PORT"; then
        echo -e "  [\033[32m✓\033[0m] $NAME (port $PORT)"
    else
        echo -e "  [\033[31m✗\033[0m] $NAME (port $PORT)"
    fi
done

echo ""
echo "━━━ Next Steps ━━━"
echo "1. Attack: sudo aireplay-ng --deauth 100 -a 9E:A8:2C:C2:1F:D9 -c 94:65:2D:97:25:87 wlan0mon"
echo "2. Watch: http://localhost:3000/prevention"
echo "3. Verify: bash scripts/verify_attack_detection.sh"
echo ""
