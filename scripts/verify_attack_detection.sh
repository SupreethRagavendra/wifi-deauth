#!/usr/bin/env bash
# verify_attack_detection.sh — Verify the sniffer detects attacks and events reach prevention
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()  { echo -e "  ${GREEN}✓${NC} $1"; }
fail(){ echo -e "  ${RED}✗${NC} $1"; }
warn(){ echo -e "  ${YELLOW}⚠${NC} $1"; }

AP_MAC="9E:A8:2C:C2:1F:D9"
VICTIM_MAC="94:65:2D:97:25:87"
ATTACK_IFACE="wlan0mon"

echo "════════════════════════════════════════════════════════════"
echo "  VERIFY ATTACK DETECTION"
echo "  AP:     $AP_MAC"
echo "  Victim: $VICTIM_MAC"
echo "  Iface:  $ATTACK_IFACE"
echo "════════════════════════════════════════════════════════════"

# 1. Attacker interface
echo -e "\n${YELLOW}[1] Attacker interface${NC}"
if iwconfig "$ATTACK_IFACE" 2>&1 | grep -q "Mode:Monitor"; then
    ok "$ATTACK_IFACE is in Monitor mode"
else
    fail "$ATTACK_IFACE is NOT in monitor mode"
    echo "  → Run: sudo airmon-ng start wlan0"
    exit 1
fi

# 2. Sniffer interface
echo -e "\n${YELLOW}[2] Sniffer interface${NC}"
SNIFF_IFACE=""
for iface in wlan2mon wlan1mon wlan2 wlan1; do
    if ip link show "$iface" &>/dev/null; then
        SNIFF_IFACE="$iface"
        break
    fi
done
if [[ -n "$SNIFF_IFACE" ]]; then
    ok "Sniffer interface: $SNIFF_IFACE"
else
    fail "No sniffer interface found"
fi

# 3. Get baseline event count from backend
echo -e "\n${YELLOW}[3] Baseline detection count${NC}"
BASELINE=$(curl -sf http://localhost:8080/api/detection/events/recent 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
ok "Current detection events: $BASELINE"

# 4. Send a short attack burst
echo -e "\n${YELLOW}[4] Sending 10 deauth frames...${NC}"
echo "  sudo aireplay-ng --deauth 10 -a $AP_MAC -c $VICTIM_MAC $ATTACK_IFACE"
sudo aireplay-ng --deauth 10 -a "$AP_MAC" -c "$VICTIM_MAC" "$ATTACK_IFACE" 2>&1 | head -8 &
ATTACK_PID=$!

# 5. Wait for detection pipeline
echo -e "\n${YELLOW}[5] Waiting 8 seconds for detection pipeline...${NC}"
sleep 8
kill "$ATTACK_PID" 2>/dev/null || true

# 6. Check new events
echo -e "\n${YELLOW}[6] Checking for new detection events${NC}"
AFTER=$(curl -sf http://localhost:8080/api/detection/events/recent 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
NEW_EVENTS=$((AFTER - BASELINE))
if [[ "$NEW_EVENTS" -gt 0 ]]; then
    ok "$NEW_EVENTS new events detected after attack!"
    echo "  Getting latest event details..."
    curl -sf http://localhost:8080/api/detection/events/recent 2>/dev/null | python3 -c "
import sys,json
evts=json.load(sys.stdin)
e=evts[0]
print(f'  eventId:     {e.get(\"eventId\")}')
print(f'  attackerMac: {e.get(\"attackerMac\")}')
print(f'  targetMac:   {e.get(\"targetMac\")}')
print(f'  totalScore:  {e.get(\"totalScore\")}')
print(f'  severity:    {e.get(\"severity\")}')
print(f'  mlConfidence:{e.get(\"mlConfidence\")}')
" 2>/dev/null || true
else
    fail "No new events detected after attack"
    echo "  Possible causes:"
    echo "  1. Sniffer not on same channel as AP"
    echo "  2. Sniffer process not running"
    echo "  3. ML detection not processing packets"
    echo "  4. Backend not storing events"
fi

# 7. Check prevention engine reaction
echo -e "\n${YELLOW}[7] Checking prevention engine reaction${NC}"
PREV_HEALTH=$(curl -sf http://localhost:5002/health 2>/dev/null || echo "FAIL")
if [[ "$PREV_HEALTH" == "FAIL" ]]; then
    fail "Prevention engine not running"
else
    PROCESSED=$(echo "$PREV_HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('events_processed',0))" 2>/dev/null || echo "?")
    ok "Engine has processed $PROCESSED total events"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "DONE"
echo "════════════════════════════════════════════════════════════"
