#!/usr/bin/env bash
# =============================================================================
# test_defense.sh — Step-by-step defense validation (run during active attack)
# =============================================================================
# PASS/FAIL each component independently before testing end-to-end.
#
# Usage: sudo bash test_defense.sh [monitor_iface]
# =============================================================================

set -euo pipefail

MON="${1:-wlan1}"
AP_MAC="${2:-9E:A8:2C:C2:1F:D9}"
VICTIM="${3:-94:65:2D:97:25:87}"
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; RST='\033[0m'

PASS=0; FAIL=0
pass() { echo -e "  ${GRN}✅ PASS${RST}: $*"; ((PASS++)) || true; }
fail() { echo -e "  ${RED}✗  FAIL${RST}: $*"; ((FAIL++)) || true; }
warn() { echo -e "  ${YLW}⚠  WARN${RST}: $*"; }

[[ $EUID -eq 0 ]] || { echo "${RED}Must run as root${RST}"; exit 1; }

echo -e "${CYN}═══════════════════════════════════════════════════════════${RST}"
echo -e "${CYN}  DEFENSE VALIDATION SUITE — $(date '+%H:%M:%S')${RST}"
echo -e "${CYN}═══════════════════════════════════════════════════════════${RST}\n"

# ─── TEST 1: Monitor interface sees attack traffic ────────────────────────
echo -e "${YLW}TEST 1: Monitor interface receives deauth frames${RST}"
echo "  Capturing for 5 seconds on $MON..."
COUNT=$(timeout 5 tcpdump -i "$MON" -nn -c 50 2>/dev/null \
    'wlan type mgt subtype deauth or wlan type mgt subtype disassoc' 2>/dev/null \
    | wc -l || echo "0")
if [[ "$COUNT" -gt 0 ]]; then
    pass "$COUNT deauth frames captured on $MON → interface is receiving attack traffic"
else
    fail "No deauth frames on $MON"
    echo "     Is attack running? Is $MON on correct channel?"
    echo "     Fix: sudo bash fix_monitor_mode.sh $MON 6"
fi

# ─── TEST 2: Injection is active ────────────────────────────────────────
echo -e "\n${YLW}TEST 2: Defense injection is active${RST}"
TX_BEFORE=$(cat /sys/class/net/"$MON"/statistics/tx_packets 2>/dev/null || echo "0")
sleep 3
TX_AFTER=$(cat /sys/class/net/"$MON"/statistics/tx_packets 2>/dev/null || echo "0")
TX_RATE=$(( (TX_AFTER - TX_BEFORE) / 3 ))

if [[ $TX_RATE -gt 500 ]]; then
    pass "Injection rate: ~${TX_RATE} frames/sec (HIGH — buffer saturation active)"
elif [[ $TX_RATE -gt 100 ]]; then
    pass "Injection rate: ~${TX_RATE} frames/sec (moderate)"
elif [[ $TX_RATE -gt 0 ]]; then
    warn "Injection rate: ~${TX_RATE} frames/sec (LOW — preemptive_shield may be throttled)"
else
    fail "NO injection detected — defense injector (preemptive_shield) is not running"
fi

# ─── TEST 3: All defense daemons running ─────────────────────────────────
echo -e "\n${YLW}TEST 3: Defense daemon process check${RST}"
for proc in preemptive_shield instant_reassoc deauth_shield; do
    if pid=$(pgrep -x "$proc" 2>/dev/null); then
        pass "$proc running (PID $pid)"
    else
        fail "$proc NOT running"
    fi
done

# ─── TEST 4: RSSI baseline check ─────────────────────────────────────────
echo -e "\n${YLW}TEST 4: RSSI baseline sanity${RST}"
echo "  Capturing 10 beacons from $AP_MAC to check RSSI..."
RSSI_VALS=$(timeout 10 tcpdump -i "$MON" -e -nn -c 10 2>/dev/null \
    "wlan type mgt subtype beacon and wlan src $AP_MAC" 2>/dev/null \
    | grep -oP 'signal: -?\d+' | grep -oP '-?\d+' || echo "")
if [[ -n "$RSSI_VALS" ]]; then
    AVG=$(echo "$RSSI_VALS" | awk '{s+=$1;n++} END {if(n>0) printf "%.0f", s/n; else print "0"}')
    if [[ $AVG -lt -25 ]]; then
        pass "AP beacon RSSI avg=${AVG} dBm (good — not loopback injection artifact)"
    else
        fail "AP beacon RSSI avg=${AVG} dBm — this is TOO LOUD (loopback injection detected!)"
        echo "     Injected frames are corrupting the RSSI baseline."
        echo "     Fix: restart make run-sniffer and check your injection interface"
    fi
else
    warn "Could not extract RSSI from beacons (tcpdump format issue)"
fi

# ─── TEST 5: Auth/reassoc frames visible on air ──────────────────────────
echo -e "\n${YLW}TEST 5: Defense auth/reassoc frames visible on air${RST}"
echo "  Checking for auth/reassoc frames from victim ${VICTIM}..."
INJECT_COUNT=$(timeout 5 tcpdump -i "$MON" -nn -c 200 2>/dev/null \
    "wlan type mgt subtype auth or wlan type mgt subtype reassoc-req" 2>/dev/null \
    | grep -c "${VICTIM,,}" 2>/dev/null || echo "0")
if [[ "$INJECT_COUNT" -gt 10 ]]; then
    pass "$INJECT_COUNT defense auth/reassoc frames visible → injector is working"
elif [[ "$INJECT_COUNT" -gt 0 ]]; then
    warn "$INJECT_COUNT defense frames in 5s (low — may throttle under heavy load)"
else
    fail "No defense auth/reassoc from victim MAC seen on air"
fi

# ─── SUMMARY ─────────────────────────────────────────────────────────────
echo -e "\n${CYN}═══════════════════════════════════════════════════════════${RST}"
echo -e "  RESULTS: ${GRN}${PASS} PASSED${RST}  ${RED}${FAIL} FAILED${RST}"
echo -e "${CYN}═══════════════════════════════════════════════════════════${RST}\n"
if [[ $FAIL -eq 0 ]]; then
    echo -e "${GRN}  All tests passed — defense system is operating correctly.${RST}"
    echo    "  If phone still disconnects, the issue is propagation timing."
    echo    "  Try: sudo bash diagnostic_suite/verify_traffic.sh wlan1 30"
else
    echo -e "${RED}  $FAIL test(s) failed — fix these before testing end-to-end.${RST}"
fi
echo ""
