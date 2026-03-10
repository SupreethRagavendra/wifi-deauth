#!/bin/bash
# ══════════════════════════════════════════════════════════════
# Prevention System Cleanup Script
# Removes ALL old prevention-related files and processes safely.
# Usage:  sudo bash scripts/cleanup_prevention.sh
# ══════════════════════════════════════════════════════════════

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "══════════════════════════════════════════════════════════"
echo "  🧹 Prevention System Cleanup"
echo "══════════════════════════════════════════════════════════"

# ── 1. Kill any running mdk4 processes ──
echo ""
echo "[1/6] Killing mdk4 processes..."
if pgrep -x mdk4 > /dev/null 2>&1; then
    killall mdk4 2>/dev/null && echo "  ✅ mdk4 processes killed" || echo "  ⚠️  Could not kill mdk4"
else
    echo "  ℹ  No mdk4 processes running"
fi

# Kill any lingering prevention engine processes
echo "[1b/6] Killing old prevention engine processes..."
if pgrep -f "prevention-engine/level1.py" > /dev/null 2>&1; then
    pkill -f "prevention-engine/level1.py" 2>/dev/null && echo "  ✅ Old engine killed" || true
else
    echo "  ℹ  No old prevention engine running"
fi

# ── 2. Remove old prevention-engine files ──
echo ""
echo "[2/6] Removing old prevention-engine files..."
PE_DIR="$PROJECT_ROOT/prevention-engine"

if [ -d "$PE_DIR" ]; then
    # Remove Python files
    rm -f "$PE_DIR"/*.py
    rm -f "$PE_DIR"/*.pyc
    rm -f "$PE_DIR"/*.sql
    rm -f "$PE_DIR"/*.txt
    rm -f "$PE_DIR"/*.yml
    rm -f "$PE_DIR"/*.yaml

    # Remove __pycache__
    rm -rf "$PE_DIR/__pycache__"

    # Remove old logs
    rm -rf "$PE_DIR/logs"

    # Remove old tests
    rm -rf "$PE_DIR/tests"

    # Remove temp files
    rm -f "$PE_DIR"/fake_aps.txt
    rm -f "$PE_DIR"/fake_clients.txt

    echo "  ✅ Old prevention-engine files removed"
else
    echo "  ℹ  No prevention-engine directory found"
fi

# ── 3. Remove old prevention scripts from backend/scripts ──
echo ""
echo "[3/6] Cleaning old prevention scripts..."
rm -f "$PROJECT_ROOT/backend/scripts/prevention"* 2>/dev/null || true
echo "  ✅ Done"

# ── 4. Clean up /var/log/wifi_defense/ ──
echo ""
echo "[4/6] Cleaning /var/log/wifi_defense/..."
if [ -d "/var/log/wifi_defense" ]; then
    rm -rf /var/log/wifi_defense/attacks/* 2>/dev/null || true
    rm -rf /var/log/wifi_defense/reports/* 2>/dev/null || true
    rm -f /var/log/wifi_defense/*.log 2>/dev/null || true
    echo "  ✅ Log files cleaned"
else
    echo "  ℹ  /var/log/wifi_defense does not exist (will be created by engine)"
fi

# ── 5. Clean temp files ──
echo ""
echo "[5/6] Cleaning temp files..."
rm -f /tmp/start_honeypot.sh 2>/dev/null || true
rm -f /tmp/stop_honeypot.sh 2>/dev/null || true
rm -f /tmp/channel_hint.txt 2>/dev/null || true
rm -f /tmp/quality_ladder.conf 2>/dev/null || true
rm -f /tmp/dual_radio.status 2>/dev/null || true
rm -f /tmp/level4_*.sh 2>/dev/null || true
rm -f /tmp/level4_*.conf 2>/dev/null || true
rm -f /tmp/level4_*.py 2>/dev/null || true
rm -f /tmp/honeypot_mdk4*.pid 2>/dev/null || true
echo "  ✅ Temp files cleaned"

# ── 6. Create fresh directory structure ──
echo ""
echo "[6/6] Creating fresh directory structure..."
mkdir -p "$PE_DIR/logs"
mkdir -p "$PE_DIR/tests"
mkdir -p /var/log/wifi_defense/attacks
mkdir -p /var/log/wifi_defense/reports
echo "  ✅ Directories created"

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  ✅ Cleanup complete! Ready for fresh installation."
echo "══════════════════════════════════════════════════════════"
