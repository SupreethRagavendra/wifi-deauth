#!/usr/bin/env bash
# =============================================================================
# verify_traffic.sh — Real-time Wi-Fi Defense Diagnostic Suite
# =============================================================================
# Runs during an active attack. Shows exactly WHERE packets are being lost:
#   1. Is wlan1 (monitor) receiving deauth frames?
#   2. Is XDP filter loaded and processing?
#   3. Are injected frames being transmitted?
#   4. What is the injection rate vs attack rate?
#
# Usage: sudo bash verify_traffic.sh [monitor_iface] [duration_sec]
# Example: sudo bash verify_traffic.sh wlan1 30
# =============================================================================

set -euo pipefail

IFACE="${1:-wlan1}"
DURATION="${2:-30}"
TMP="/tmp/wifi_diag_$$"
mkdir -p "$TMP"
trap "rm -rf $TMP" EXIT

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; RST='\033[0m'

check_root() {
    [[ $EUID -eq 0 ]] || { echo -e "${RED}✗ Must run as root${RST}"; exit 1; }
}

banner() {
    echo -e "${CYN}═══════════════════════════════════════════════════════════${RST}"
    echo -e "${CYN}  Wi-Fi Defense Diagnostic — $(date '+%H:%M:%S')${RST}"
    echo -e "${CYN}  Interface: $IFACE   Duration: ${DURATION}s${RST}"
    echo -e "${CYN}═══════════════════════════════════════════════════════════${RST}"
}

# ─── CHECK 1: Interface state ─────────────────────────────────────────────
check_interface() {
    echo -e "\n${YLW}[CHECK 1] Interface ${IFACE} state${RST}"

    if ! ip link show "$IFACE" &>/dev/null; then
        echo -e "${RED}  ✗ Interface $IFACE does not exist!${RST}"
        echo "     Available wireless interfaces:"
        iw dev | grep Interface | awk '{print "       " $2}'
        return 1
    fi

    local operstate mode channel txpower
    operstate=$(cat /sys/class/net/"$IFACE"/operstate 2>/dev/null || echo "unknown")
    mode=$(iw dev "$IFACE" info 2>/dev/null | grep type | awk '{print $2}')
    channel=$(iw dev "$IFACE" info 2>/dev/null | grep channel | awk '{print $2}')
    txpower=$(iw dev "$IFACE" info 2>/dev/null | grep txpower | awk '{print $2}')

    echo "  State    : $operstate"
    echo "  Mode     : ${mode:-UNKNOWN}"
    echo "  Channel  : ${channel:-UNKNOWN}"
    echo "  TX Power : ${txpower:-UNKNOWN} dBm"

    [[ "$mode" == "monitor" ]] && echo -e "  ${GRN}✅ In monitor mode${RST}" \
        || echo -e "  ${RED}✗ NOT in monitor mode (mode=$mode) — sniffer won't work!${RST}"
    [[ "$operstate" == "up" ]] && echo -e "  ${GRN}✅ Interface is UP${RST}" \
        || echo -e "  ${RED}✗ Interface is DOWN — use fix_monitor_mode.sh${RST}"
}

# ─── CHECK 2: XDP filter ────────────────────────────────────────────────
check_xdp() {
    echo -e "\n${YLW}[CHECK 2] XDP filter status${RST}"

    if ! command -v bpftool &>/dev/null; then
        echo -e "  ${RED}✗ bpftool not installed (apt install bpftool)${RST}"
        return
    fi

    local xdp_prog
    xdp_prog=$(bpftool net show dev "$IFACE" 2>/dev/null | grep xdp | head -1)
    if [[ -n "$xdp_prog" ]]; then
        echo -e "  ${GRN}✅ XDP program loaded:${RST} $xdp_prog"
    else
        echo -e "  ${RED}✗ NO XDP program on $IFACE${RST}"
        echo "     Load with: sudo ip link set $IFACE xdp obj xdp_deauth_defense.o sec xdp"
    fi

    local prog_count
    prog_count=$(bpftool prog show 2>/dev/null | grep -c "xdp" || echo "0")
    echo "  Total XDP programs loaded: $prog_count"

    if [[ "$prog_count" -gt 0 ]]; then
        echo "  XDP programs:"
        bpftool prog show 2>/dev/null | grep -A2 "xdp" | head -20
    fi
}

# ─── CHECK 3: Live deauth frame capture ──────────────────────────────────
check_deauth_rx() {
    echo -e "\n${YLW}[CHECK 3] Capturing deauth frames on $IFACE for ${DURATION}s${RST}"
    echo "  (Run your attack in another terminal now...)"
    echo ""

    local cap_file="$TMP/capture.pcap"
    local result_file="$TMP/deauth_count.txt"

    # Background capture
    timeout "$DURATION" tcpdump -i "$IFACE" -w "$cap_file" \
        -nn --no-promiscuous-mode \
        'wlan type mgt subtype deauth or wlan type mgt subtype disassoc' \
        2>/dev/null &
    local tcpd_pid=$!

    # Real-time counter
    local count=0
    local elapsed=0
    while kill -0 $tcpd_pid 2>/dev/null && [[ $elapsed -lt $DURATION ]]; do
        sleep 2
        elapsed=$((elapsed + 2))
        local frames
        frames=$(tcpdump -r "$cap_file" -nn 2>/dev/null | wc -l 2>/dev/null || echo "0")
        local rate=$(( (frames - count) / 2 ))
        count=$frames
        printf "\r  %3ds: %6d deauth frames captured | ~%3d/sec    " \
               "$elapsed" "$frames" "$rate"
    done
    echo ""

    wait $tcpd_pid 2>/dev/null || true
    local total
    total=$(tcpdump -r "$cap_file" -nn 2>/dev/null | wc -l 2>/dev/null || echo "0")

    if [[ "$total" -gt 0 ]]; then
        echo -e "  ${GRN}✅ Captured $total deauth/disassoc frames${RST}"
        echo ""
        echo "  Top source MACs:"
        tcpdump -r "$cap_file" -nn 2>/dev/null \
            | grep -oP 'SA:[0-9a-f:]+' | sort | uniq -c | sort -rn | head -5 \
            | awk '{printf "    %-6s frames from %s\n", $1, $2}'
        echo ""
        echo "  First frame (hexdump of radiotap header):"
        tcpdump -r "$cap_file" -nn -x -c 1 2>/dev/null | head -5 | sed 's/^/    /'
    else
        echo -e "  ${RED}✗ NO deauth frames captured on $IFACE${RST}"
        echo "     Possible causes:"
        echo "     1. Attacker is on different channel than $IFACE"
        echo "     2. $IFACE is not in monitor mode"
        echo "     3. Attack not running yet"
    fi
}

# ─── CHECK 4: Injected frame TX verification ─────────────────────────────
check_injection_tx() {
    echo -e "\n${YLW}[CHECK 4] Injection TX rate verification${RST}"

    local stat_before stat_after
    stat_before=$(cat /sys/class/net/"$IFACE"/statistics/tx_packets 2>/dev/null || echo "0")
    sleep 3
    stat_after=$(cat /sys/class/net/"$IFACE"/statistics/tx_packets 2>/dev/null || echo "0")
    local rate=$(( (stat_after - stat_before) / 3 ))

    echo "  TX packets in 3s: $((stat_after - stat_before))"
    echo "  TX rate: ~${rate} packets/sec"

    if [[ $rate -gt 100 ]]; then
        echo -e "  ${GRN}✅ Active injection detected (${rate}/sec)${RST}"
    elif [[ $rate -gt 0 ]]; then
        echo -e "  ${YLW}⚠ Low injection rate (${rate}/sec) — preemptive_shield may not be running${RST}"
    else
        echo -e "  ${RED}✗ NO injection detected — preemptive_shield is not running!${RST}"
        echo "     Build: make build-preemptive-shield"
    fi

    # Check preemptive_shield process
    if pgrep -x preemptive_shield &>/dev/null; then
        echo -e "  ${GRN}✅ preemptive_shield process running${RST}"
    else
        echo -e "  ${RED}✗ preemptive_shield NOT running${RST}"
    fi

    if pgrep -x instant_reassoc &>/dev/null; then
        echo -e "  ${GRN}✅ instant_reassoc process running${RST}"
    else
        echo -e "  ${RED}✗ instant_reassoc NOT running${RST}"
    fi

    if pgrep -x deauth_shield &>/dev/null; then
        echo -e "  ${GRN}✅ deauth_shield process running${RST}"
    else
        echo -e "  ${RED}✗ deauth_shield NOT running${RST}"
    fi
}

# ─── CHECK 5: Channel alignment ───────────────────────────────────────────
check_channel_alignment() {
    echo -e "\n${YLW}[CHECK 5] Channel alignment verification${RST}"

    local ifaces
    ifaces=$(iw dev | grep -E "^[[:space:]]*Interface" | awk '{print $2}')

    echo "  All wireless interfaces:"
    for iface in $ifaces; do
        local ch mode
        ch=$(iw dev "$iface" info 2>/dev/null | grep channel | awk '{print $2}')
        mode=$(iw dev "$iface" info 2>/dev/null | grep type | awk '{print $2}')
        printf "    %-12s mode=%-9s channel=%s\n" "$iface" "${mode:-?}" "${ch:-?}"
    done

    local mon_ch ap_ch
    mon_ch=$(iw dev "$IFACE" info 2>/dev/null | grep channel | awk '{print $2}')

    # Try to find AP interface (non-monitor, same phy)
    local phy
    phy=$(iw dev "$IFACE" info 2>/dev/null | grep wiphy | awk '{print "phy" $2}')
    echo ""
    echo "  Monitor interface:  ${IFACE} → channel ${mon_ch:-UNKNOWN}"
    echo "  Physical radio:     $phy"

    if [[ -n "$mon_ch" ]]; then
        if [[ "$mon_ch" == "6" ]]; then
            echo -e "  ${GRN}✅ Monitor is on channel 6 (AP channel)${RST}"
        else
            echo -e "  ${RED}✗ Monitor is on channel $mon_ch — AP is probably on channel 6!${RST}"
            echo "     Fix: sudo iwconfig $IFACE channel 6"
        fi
    fi
}

# ─── CHECK 6: Competing processes ─────────────────────────────────────────
check_competing_processes() {
    echo -e "\n${YLW}[CHECK 6] Competing process check${RST}"

    local nm_status
    nm_status=$(systemctl is-active NetworkManager 2>/dev/null || echo "unknown")
    if [[ "$nm_status" == "active" ]]; then
        echo -e "  ${YLW}⚠ NetworkManager is ACTIVE — may interfere with monitor mode${RST}"
        echo "     Fix: sudo systemctl stop NetworkManager"
    else
        echo -e "  ${GRN}✅ NetworkManager: $nm_status${RST}"
    fi

    if pgrep -x wpa_supplicant &>/dev/null; then
        echo -e "  ${YLW}⚠ wpa_supplicant running (PID $(pgrep -x wpa_supplicant)) — may reset interface${RST}"
    else
        echo -e "  ${GRN}✅ wpa_supplicant: not running${RST}"
    fi

    if pgrep -x hostapd &>/dev/null; then
        echo -e "  ${GRN}✅ hostapd running (AP is up)${RST}"
    else
        echo -e "  ${YLW}⚠ hostapd NOT running — is the AP up?${RST}"
    fi
}

# ─── MAIN ──────────────────────────────────────────────────────────────────
check_root
banner
check_interface
check_xdp
check_channel_alignment
check_competing_processes
check_injection_tx
check_deauth_rx  # last — takes DURATION seconds with live capture

echo -e "\n${CYN}═══════════════════════════════════════════════════════════${RST}"
echo -e "${GRN}  Diagnostic complete. Outputs saved to: $TMP/${RST}"
echo -e "${CYN}═══════════════════════════════════════════════════════════${RST}\n"
