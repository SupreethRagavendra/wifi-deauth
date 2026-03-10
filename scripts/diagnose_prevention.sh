#!/usr/bin/env bash
# diagnose_prevention.sh — Full pipeline diagnostic
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()  { echo -e "  ${GREEN}✓${NC} $1"; }
fail(){ echo -e "  ${RED}✗${NC} $1"; }
warn(){ echo -e "  ${YELLOW}⚠${NC} $1"; }
hr()  { echo "════════════════════════════════════════════════════════════"; }

ROOT_CAUSES=()

hr
echo "PREVENTION SYSTEM DIAGNOSTICS"
echo "Time: $(date)"
hr

# ─────── [1] SNIFFER STATUS ───────
echo -e "\n${YELLOW}[1] SNIFFER STATUS${NC}"
if ip link show wlan2mon &>/dev/null; then
    MODE=$(iwconfig wlan2mon 2>/dev/null | grep -oP 'Mode:\K\S+' || echo "unknown")
    if [[ "$MODE" == "Monitor" ]]; then
        ok "wlan2mon in Monitor mode"
    else
        fail "wlan2mon exists but mode=$MODE (need Monitor)"
        ROOT_CAUSES+=("Sniffer interface not in monitor mode")
    fi
else
    fail "wlan2mon does NOT exist"
    warn "Look for other monitor interfaces:"
    ip link show 2>/dev/null | grep -E 'wlan|mon' || echo "  (none found)"
    ROOT_CAUSES+=("No monitor interface")
fi

if pgrep -f "sniffer\|packet_sniffer\|run-sniffer" &>/dev/null; then
    ok "Sniffer process running"
else
    fail "No sniffer process found"
    ROOT_CAUSES+=("Sniffer process not running")
fi

# ─────── [2] BACKEND API (Spring Boot :8080) ───────
echo -e "\n${YELLOW}[2] BACKEND API STATUS${NC}"
if curl -sf http://localhost:8080/actuator/health -o /dev/null 2>/dev/null; then
    ok "Spring Boot running (port 8080)"
else
    if ss -tlnp 2>/dev/null | grep -q ':8080'; then
        ok "Port 8080 open (backend starting?)"
    else
        fail "Backend NOT running on port 8080"
        ROOT_CAUSES+=("Spring Boot backend is down")
    fi
fi

# Try detection endpoint (unauthenticated — will fall back to global)
EVENTS_JSON=$(curl -sf http://localhost:8080/api/detection/events/recent 2>/dev/null || echo "FAIL")
if [[ "$EVENTS_JSON" == "FAIL" ]]; then
    fail "/api/detection/events/recent — cannot reach endpoint"
    ROOT_CAUSES+=("Backend detection endpoint unreachable")
else
    EVENT_COUNT=$(echo "$EVENTS_JSON" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null | head -1 || echo "0")
    if [[ "$EVENT_COUNT" -gt 0 ]]; then
        ok "Backend has $EVENT_COUNT detection events"
        # Check if any have high confidence
        HIGH_CONF=$(echo "$EVENTS_JSON" | python3 -c "
import sys,json
evts=json.load(sys.stdin)
high=[e for e in evts if (e.get('totalScore',0) or 0)>=40 or (e.get('mlConfidence',0) or 0)>=0.4]
print(len(high))
" 2>/dev/null || echo "0")
        if [[ "$HIGH_CONF" -gt 0 ]]; then
            ok "$HIGH_CONF events with score≥40 (prevention should trigger)"
        else
            warn "All $EVENT_COUNT events have score<40 (below L1 threshold)"
            ROOT_CAUSES+=("Detection scores too low to trigger prevention (all <40)")
        fi
    else
        fail "Backend returns 0 detection events"
        ROOT_CAUSES+=("No detection events stored in backend database")
    fi
fi

# ─────── [3] ML DETECTION SERVICE (:5000) ───────
echo -e "\n${YELLOW}[3] ML DETECTION SERVICE${NC}"
if curl -sf http://localhost:5000/health -o /dev/null 2>/dev/null; then
    ok "ML detection service running (port 5000)"
elif ss -tlnp 2>/dev/null | grep -q ':5000'; then
    ok "ML service port 5000 is open"
else
    fail "ML detection service NOT running"
    ROOT_CAUSES+=("ML detection service is down")
fi

# ─────── [4] PREVENTION ENGINE (:5002) ───────
echo -e "\n${YELLOW}[4] PREVENTION ENGINE STATUS${NC}"
HEALTH_JSON=$(curl -sf http://localhost:5002/health 2>/dev/null || echo "FAIL")
if [[ "$HEALTH_JSON" == "FAIL" ]]; then
    fail "Prevention engine NOT running on port 5002"
    ROOT_CAUSES+=("Prevention engine is down (Flask not running)")
else
    ok "Prevention engine running"
    RUNNING=$(echo "$HEALTH_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('running',False))" 2>/dev/null)
    PROCESSED=$(echo "$HEALTH_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('events_processed',0))" 2>/dev/null)
    LAST_POLL=$(echo "$HEALTH_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('last_poll','never'))" 2>/dev/null)
    if [[ "$RUNNING" == "True" ]]; then
        ok "Engine running=True, processed=$PROCESSED events, last_poll=$LAST_POLL"
    else
        fail "Engine exists but running=False (poll loop stopped?)"
        ROOT_CAUSES+=("Engine poll loop is stopped")
    fi
fi

# Engine stats
STATS_JSON=$(curl -sf http://localhost:5002/stats 2>/dev/null || echo "FAIL")
if [[ "$STATS_JSON" != "FAIL" ]]; then
    TOTAL=$(echo "$STATS_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo "0")
    ok "Prevention DB has $TOTAL total events"
fi

# ─────── [5] PREVENTION ENGINE LOG HEALTH ───────
echo -e "\n${YELLOW}[5] ENGINE LOGS${NC}"
ENGINE_LOG="prevention-engine/logs/engine.log"
COMP_LOG="prevention-engine/logs/components.log"
if [[ -f "$ENGINE_LOG" ]]; then
    ok "Engine log exists ($(wc -l < "$ENGINE_LOG") lines)"
    LAST_5=$(tail -5 "$ENGINE_LOG" 2>/dev/null || echo "(empty)")
    echo "  Last 5 lines:"
    echo "$LAST_5" | sed 's/^/    /'
    # Check for errors
    ERRORS=$(grep -c "ERROR" "$ENGINE_LOG" 2>/dev/null | head -1 || echo "0")
    if [[ "$ERRORS" -gt 0 ]]; then
        warn "$ERRORS errors in engine log"
    fi
else
    fail "Engine log not found at $ENGINE_LOG"
fi

if [[ -f "$COMP_LOG" ]]; then
    ok "Components log exists ($(wc -l < "$COMP_LOG") lines)"
else
    warn "Components log not found (components never fired?)"
fi

# ─────── [6] DATABASE ───────
echo -e "\n${YELLOW}[6] DATABASE CHECK${NC}"
DB_CHECK=$(curl -sf http://localhost:5002/prevention/events?limit=1 2>/dev/null || echo "FAIL")
if [[ "$DB_CHECK" == "FAIL" ]]; then
    warn "Cannot reach prevention events endpoint"
else
    ok "Prevention events endpoint reachable"
fi

# ─────── [7] DASHBOARD CONNECTIVITY ───────
echo -e "\n${YELLOW}[7] DASHBOARD CONNECTIVITY${NC}"
if curl -sf http://localhost:3000 -o /dev/null 2>/dev/null; then
    ok "Frontend running (port 3000)"
else
    fail "Frontend NOT running on port 3000"
    ROOT_CAUSES+=("Frontend is down")
fi

# ─────── [8] NETWORK TOPOLOGY ───────
echo -e "\n${YELLOW}[8] REGISTERED NETWORKS${NC}"
WIFI_JSON=$(curl -sf http://localhost:8080/api/wifi 2>/dev/null || echo "FAIL")
if [[ "$WIFI_JSON" == "FAIL" ]]; then
    warn "Cannot reach /api/wifi (backend may need auth)"
else
    NET_COUNT=$(echo "$WIFI_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('data',d) if isinstance(d,dict) else d))" 2>/dev/null || echo "?")
    ok "Registered networks: $NET_COUNT"
fi

# ─────── SUMMARY ───────
echo ""
hr
echo "ROOT CAUSES IDENTIFIED:"
if [[ ${#ROOT_CAUSES[@]} -eq 0 ]]; then
    echo -e "  ${GREEN}No critical issues found — pipeline looks healthy${NC}"
else
    for i in "${!ROOT_CAUSES[@]}"; do
        echo -e "  ${RED}$((i+1)). ${ROOT_CAUSES[$i]}${NC}"
    done
fi
hr

echo ""
echo "RECOMMENDED FIXES:"
echo "1. Start all services:  make run-backend  (new terminal)"
echo "2. Start prevention:    sudo python3 prevention-engine/level1.py"
echo "3. Start sniffer:       make run-sniffer CHANNEL=1"
echo "4. Start frontend:      make run-frontend"
echo "5. Attack:              sudo aireplay-ng --deauth 100 -a 9E:A8:2C:C2:1F:D9 -c 94:65:2D:97:25:87 wlan0mon"
echo "6. Open dashboard:      http://localhost:3000/prevention"
hr
