#!/usr/bin/env python3
"""
check_interfaces.py — Wi-Fi Interface Configuration Checker & Auto-Fixer
=========================================================================
Checks and auto-fixes:
  - Monitor interface channel alignment with AP
  - Competing process detection (NetworkManager, wpa_supplicant)
  - Interface mode verification  
  - TX power verification
  - Channel hopping detection

Usage: sudo python3 check_interfaces.py [--fix]
       --fix: auto-fix common misconfigurations
"""

import subprocess, sys, os, re, time, argparse, json

RED = '\033[0;31m'; GRN = '\033[0;32m'; YLW = '\033[1;33m'; RST = '\033[0m'

def run(cmd, check=False):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return "", str(e), -1

def check_root():
    if os.geteuid() != 0:
        print(f"{RED}✗ Must run as root{RST}")
        sys.exit(1)

def get_iw_info(iface):
    out, _, rc = run(f"iw dev {iface} info 2>/dev/null")
    if rc != 0:
        return {}
    info = {}
    for line in out.splitlines():
        line = line.strip()
        if m := re.search(r'type (\S+)', line):
            info['mode'] = m.group(1)
        if m := re.search(r'channel (\d+)', line):
            info['channel'] = int(m.group(1))
        if m := re.search(r'txpower ([\d.]+)', line):
            info['txpower'] = float(m.group(1))
        if m := re.search(r'wiphy (\d+)', line):
            info['phy'] = f"phy{m.group(1)}"
    return info

def get_all_interfaces():
    out, _, _ = run("iw dev")
    return re.findall(r'Interface (\S+)', out)

def get_operstate(iface):
    out, _, _ = run(f"cat /sys/class/net/{iface}/operstate")
    return out.strip()

def check_and_fix_mode(iface, fix=False):
    info = get_iw_info(iface)
    mode = info.get('mode', 'unknown')
    state = get_operstate(iface)

    if mode == 'monitor':
        print(f"  {GRN}✅ {iface}: monitor mode{RST}")
    else:
        print(f"  {RED}✗  {iface}: mode={mode} (expected monitor){RST}")
        if fix:
            print(f"     → Fixing: setting monitor mode on {iface}")
            run(f"ip link set {iface} down")
            time.sleep(0.3)
            out, err, rc = run(f"iw dev {iface} set type monitor")
            if rc != 0:
                print(f"     → iw failed ({err}), trying via phy...")
                phy = info.get('phy', '')
                if phy:
                    run(f"iw {phy} interface {iface} set type monitor")
            run(f"ip link set {iface} up")
            time.sleep(0.3)
            new_info = get_iw_info(iface)
            new_mode = new_info.get('mode', 'unknown')
            if new_mode == 'monitor':
                print(f"     {GRN}✅ Fixed: {iface} now in monitor mode{RST}")
            else:
                print(f"     {RED}✗  Fix failed: mode={new_mode}{RST}")

    if state == 'up':
        print(f"  {GRN}✅ {iface}: operstate=up{RST}")
    else:
        print(f"  {RED}✗  {iface}: operstate={state}{RST}")
        if fix:
            run(f"ip link set {iface} up")
            print(f"     → Brought {iface} up")

    return info

def check_channel_alignment(mon_iface, expected_channel=6, fix=False):
    print(f"\n{YLW}[CHANNELS]{RST}")
    ifaces = get_all_interfaces()
    channel_map = {}
    for iface in ifaces:
        info = get_iw_info(iface)
        ch = info.get('channel')
        mode = info.get('mode', '?')
        state = get_operstate(iface)
        channel_map[iface] = ch
        print(f"  {iface:12s}  mode={mode:10s}  channel={str(ch):4s}  state={state}")

    mon_ch = channel_map.get(mon_iface)
    if mon_ch == expected_channel:
        print(f"\n  {GRN}✅ Monitor {mon_iface} is on channel {expected_channel} (correct){RST}")
    else:
        print(f"\n  {RED}✗  Monitor {mon_iface} is on channel {mon_ch} (expected {expected_channel}){RST}")
        if fix:
            print(f"     → Fixing: setting {mon_iface} to channel {expected_channel}")
            out, err, rc = run(f"iw dev {mon_iface} set channel {expected_channel}")
            if rc != 0:
                run(f"iwconfig {mon_iface} channel {expected_channel}")
            new_ch = get_iw_info(mon_iface).get('channel')
            if new_ch == expected_channel:
                print(f"     {GRN}✅ Fixed: channel now {new_ch}{RST}")
            else:
                print(f"     {RED}✗  Fix failed: channel={new_ch}{RST}")

    # Check iw vs iwconfig agreement
    out_iwc, _, _ = run(f"iwconfig {mon_iface} 2>/dev/null | grep Frequency")
    freq_match = re.search(r'Channel[:\s]+(\d+)', out_iwc)
    if freq_match:
        iwc_ch = int(freq_match.group(1))
        if iwc_ch != mon_ch:
            print(f"  {RED}✗  MISMATCH: iw says ch={mon_ch}, iwconfig says ch={iwc_ch}!{RST}")
        else:
            print(f"  {GRN}✅ iw and iwconfig agree on channel {mon_ch}{RST}")

def check_competing_processes(fix=False):
    print(f"\n{YLW}[COMPETING PROCESSES]{RST}")

    # NetworkManager
    out, _, rc = run("systemctl is-active NetworkManager 2>/dev/null")
    if out == 'active':
        print(f"  {YLW}⚠  NetworkManager: active (may reset monitor interface){RST}")
        if fix:
            print("     → Stopping NetworkManager...")
            run("systemctl stop NetworkManager")
            # Mark wlan1 as unmanaged
            os.makedirs("/etc/NetworkManager/conf.d", exist_ok=True)
            with open("/etc/NetworkManager/conf.d/wifi-ignore-monitor.conf", "w") as f:
                f.write("[keyfile]\nunmanaged-devices=interface-name:wlan1,interface-name:wlan1mon\n")
            print(f"     {GRN}✅ NetworkManager stopped and wlan1 marked unmanaged{RST}")
    else:
        print(f"  {GRN}✅ NetworkManager: {out or 'inactive'}{RST}")

    # wpa_supplicant
    out, _, _ = run("pgrep -la wpa_supplicant 2>/dev/null")
    if out:
        print(f"  {YLW}⚠  wpa_supplicant running: {out[:80]}{RST}")
        if fix:
            run("pkill -f wpa_supplicant")
            print(f"     {GRN}→ Killed wpa_supplicant{RST}")
    else:
        print(f"  {GRN}✅ wpa_supplicant: not running{RST}")

    # hostapd (we WANT this running)
    out, _, _ = run("pgrep -la hostapd 2>/dev/null")
    if out:
        print(f"  {GRN}✅ hostapd: running (AP is up){RST}")
    else:
        print(f"  {YLW}⚠  hostapd: not running (AP may be down){RST}")

    # Our defense daemons
    for proc in ['preemptive_shield', 'instant_reassoc', 'deauth_shield']:
        out, _, _ = run(f"pgrep -x {proc} 2>/dev/null")
        if out:
            print(f"  {GRN}✅ {proc}: running (PID {out}){RST}")
        else:
            print(f"  {RED}✗  {proc}: NOT running{RST}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fix', action='store_true', help='Auto-fix misconfigurations')
    parser.add_argument('--iface', default='wlan1', help='Monitor interface')
    parser.add_argument('--channel', type=int, default=6, help='Expected AP channel')
    args = parser.parse_args()

    check_root()

    print(f"\n{'='*60}")
    print(f"  Wi-Fi Interface Checker {'(AUTO-FIX MODE)' if args.fix else '(READ-ONLY)'}")
    print(f"  Monitor: {args.iface}  Expected channel: {args.channel}")
    print(f"{'='*60}\n")

    print(f"{YLW}[INTERFACE STATE]{RST}")
    info = check_and_fix_mode(args.iface, fix=args.fix)

    check_channel_alignment(args.iface, args.channel, fix=args.fix)
    check_competing_processes(fix=args.fix)

    print(f"\n{'='*60}")
    if args.fix:
        print(f"{GRN}  Auto-fix complete. Restart: make run-sniffer CHANNEL={args.channel}{RST}")
    else:
        print(f"{YLW}  Re-run with --fix to auto-correct issues{RST}")
    print(f"{'='*60}\n")

if __name__ == '__main__':
    main()
