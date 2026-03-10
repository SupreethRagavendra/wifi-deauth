#!/usr/bin/env bash
# =============================================================================
# fix_monitor_mode.sh — Properly configure wlan1 for monitor mode
# =============================================================================
# Kills interfering processes, sets monitor mode correctly using iw,
# sets channel 6, maximizes TX power. Safe to re-run.
#
# Usage: sudo bash fix_monitor_mode.sh [interface] [channel]
# Example: sudo bash fix_monitor_mode.sh wlan1 6
# =============================================================================

set -euo pipefail

IFACE="${1:-wlan1}"
CHANNEL="${2:-6}"
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; RST='\033[0m'

[[ $EUID -eq 0 ]] || { echo -e "${RED}✗ Must run as root${RST}"; exit 1; }

log() { echo -e "${GRN}[+]${RST} $*"; }
warn() { echo -e "${YLW}[!]${RST} $*"; }
die() { echo -e "${RED}[✗]${RST} $*"; exit 1; }

log "=== fix_monitor_mode.sh: $IFACE → monitor mode, channel $CHANNEL ==="

# ── STEP 1: Unblock rfkill ─────────────────────────────────────────────────
log "Step 1: Checking rfkill"
if rfkill list | grep -q "Soft blocked: yes"; then
    warn "rfkill soft-blocked: unblocking..."
    rfkill unblock wifi
    sleep 1
fi
log "rfkill: OK"

# ── STEP 2: Kill competing processes ─────────────────────────────────────
log "Step 2: Killing competing processes"

# Kill NetworkManager only if it manages this interface
if systemctl is-active NetworkManager &>/dev/null; then
    warn "Stopping NetworkManager (will restart at end)"
    systemctl stop NetworkManager
    NM_WAS_RUNNING=1
else
    NM_WAS_RUNNING=0
fi

# Kill wpa_supplicant on this interface
pkill -f "wpa_supplicant.*$IFACE" 2>/dev/null && warn "Killed wpa_supplicant on $IFACE" || true
# Kill any airmon-ng/airbase-ng holding the interface
pkill -f "airbase-ng.*$IFACE" 2>/dev/null || true
pkill -f "airodump-ng.*$IFACE" 2>/dev/null || true
# Kill our own sniffer in case it's running
pkill -f "python3.*main.py" 2>/dev/null && warn "Killed packet sniffer (restart it after)" || true

sleep 1
log "Competing processes: cleared"

# ── STEP 3: Bring interface down, set monitor mode ────────────────────────
log "Step 3: Configuring $IFACE as monitor"

# Bring down
if ! ip link set "$IFACE" down 2>/dev/null; then
    die "Cannot bring $IFACE down: $(ip link show $IFACE 2>&1)"
fi
sleep 0.3

# Set monitor mode using iw (not iwconfig — more reliable)
if ! iw dev "$IFACE" set type monitor 2>/dev/null; then
    # Try via phy
    PHY=$(iw dev "$IFACE" info 2>/dev/null | grep wiphy | awk '{print "phy" $2}')
    if [[ -n "$PHY" ]]; then
        warn "Direct mode set failed, trying via $PHY..."
        iw "$PHY" interface "$IFACE" set type monitor 2>/dev/null \
            || die "Cannot set monitor mode on $IFACE"
    else
        die "Cannot set monitor mode — interface $IFACE might need airmon-ng"
    fi
fi

# Bring up
ip link set "$IFACE" up || die "Cannot bring $IFACE up"
sleep 0.5

# ── STEP 4: Set channel ────────────────────────────────────────────────────
log "Step 4: Setting channel $CHANNEL"
if ! iw dev "$IFACE" set channel "$CHANNEL" 2>/dev/null; then
    warn "iw channel set failed — trying iwconfig"
    iwconfig "$IFACE" channel "$CHANNEL" 2>/dev/null \
        || warn "Channel set failed (may self-correct when AP starts)"
else
    log "Channel $CHANNEL set successfully"
fi

# ── STEP 5: Maximize TX power ──────────────────────────────────────────────
log "Step 5: Setting TX power"
# Get regulatory domain max
REG_MAX=$(iw reg get 2>/dev/null | grep "max_eirp" | head -1 | grep -oP '[0-9.]+' | head -1)
if [[ -n "$REG_MAX" ]]; then
    TX_DBM=$(echo "$REG_MAX / 100" | bc 2>/dev/null || echo "30")
    iw dev "$IFACE" set txpower fixed "${TX_DBM}00" 2>/dev/null \
        || warn "TX power set failed (may need different driver)"
    log "TX power: ${TX_DBM} dBm"
else
    warn "Could not determine regulatory max TX power"
fi

# ── STEP 6: Verify ────────────────────────────────────────────────────────
log "Step 6: Verifying configuration"
echo ""
iw dev "$IFACE" info
echo ""

MODE=$(iw dev "$IFACE" info | grep type | awk '{print $2}')
CH=$(iw dev "$IFACE" info | grep channel | awk '{print $2}')
STATE=$(cat /sys/class/net/"$IFACE"/operstate 2>/dev/null)

[[ "$MODE" == "monitor" ]] \
    && log "✅ Mode    : monitor" \
    || warn "✗  Mode    : $MODE (WRONG!)"
[[ "$CH" == "$CHANNEL" ]] \
    && log "✅ Channel : $CH" \
    || warn "✗  Channel : $CH (expected $CHANNEL)"
[[ "$STATE" == "up" ]] \
    && log "✅ State   : up" \
    || warn "✗  State   : $STATE (WRONG!)"

# ── STEP 7: Restart NetworkManager if it was running ─────────────────────
if [[ "${NM_WAS_RUNNING:-0}" == "1" ]]; then
    warn "Restarting NetworkManager (will ignore $IFACE)"
    # Add wifi.scan-rand-mac-address=no to NM config to stop it from
    # touching monitor interfaces
    mkdir -p /etc/NetworkManager/conf.d
    cat > /etc/NetworkManager/conf.d/wifi-ignore-monitor.conf << 'NMCONF'
[keyfile]
unmanaged-devices=interface-name:wlan1,interface-name:wlan1mon
[device]
wifi.scan-rand-mac-address=no
NMCONF
    systemctl start NetworkManager
    log "NetworkManager restarted (wlan1 marked unmanaged)"
fi

echo ""
log "=== Done. You can now run: make run-sniffer CHANNEL=$CHANNEL ==="
