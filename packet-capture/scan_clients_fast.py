#!/usr/bin/env python3
"""
Fast client scanner using ARP table and nmap ping scan.
Does NOT require monitor mode - works on normal managed interface.
Used by Viewer Settings to quickly list connected clients.
"""
import subprocess
import json
import sys
import os
import re

# Common OUI database
OUI_DATABASE = {
    "94:65:2D": "Apple",
    "00:1A:11": "Google",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "AC:DE:48": "Xiaomi",
    "34:CE:00": "Xiaomi",
    "3C:37:86": "LG Electronics",
    "00:24:D7": "Intel",
    "D8:9E:F3": "Intel",
    "00:26:B6": "ASUS",
    "2C:56:DC": "ASUS",
    "4C:6F:9C": "OPPO",
    "6C:24:A6": "Vivo",
    "10:B1:DF": "Samsung",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "A0:86:C6": "Murata",
    "9E:A8:2C": "Router/AP",
}

_vendor_cache = {}

def get_vendor(mac_address):
    """Get vendor from local OUI database (instant, no API calls)."""
    if not mac_address:
        return "Unknown"
    if mac_address in _vendor_cache:
        return _vendor_cache[mac_address]
    
    mac_upper = mac_address.upper()
    oui = ':'.join(mac_upper.split(':')[:3])
    vendor = OUI_DATABASE.get(oui, "Unknown")
    _vendor_cache[mac_address] = vendor
    return vendor


def get_hostname(ip_address):
    """Try to resolve hostname from IP."""
    try:
        result = subprocess.run(
            ['avahi-resolve', '-a', ip_address],
            capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                return parts[1].rstrip('.')
    except:
        pass
    
    try:
        result = subprocess.run(
            ['getent', 'hosts', ip_address],
            capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                return parts[1]
    except:
        pass
    
    return "Unknown"


def scan_arp_table():
    """Read current ARP table for connected devices — instant."""
    clients = []
    seen_macs = set()
    
    try:
        with open('/proc/net/arp', 'r') as f:
            lines = f.readlines()
        
        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 6:
                ip = parts[0]
                flags = parts[2]
                mac = parts[3].upper()
                
                # Skip incomplete entries and broadcast
                if mac == "00:00:00:00:00:00" or flags == "0x0":
                    continue
                if mac in seen_macs:
                    continue
                seen_macs.add(mac)
                
                vendor = get_vendor(mac)
                # Skip the router/AP itself
                if vendor == "Router/AP":
                    continue
                
                hostname = get_hostname(ip)
                
                clients.append({
                    "macAddress": mac,
                    "ipAddress": ip,
                    "hostname": hostname if hostname != "Unknown" else vendor,
                    "signalStrength": "N/A",
                    "connectionTime": ""
                })
    except Exception as e:
        sys.stderr.write(f"Error reading ARP table: {e}\n")
    
    return clients


def scan_nmap_quick(subnet="192.168.1.0/24"):
    """Quick ping scan to refresh ARP table, then read it. No sudo needed."""
    try:
        # Use fping for fast parallel ping (no sudo needed)
        # Falls back to nmap without sudo, then to basic ping
        try:
            subprocess.run(['fping', '-a', '-g', subnet, '-q', '-t', '200', '-r', '0'],
                          capture_output=True, timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Fallback: nmap without sudo (limited but works for ARP refresh)
            try:
                subprocess.run(['nmap', '-sn', '-T5', '--min-rate=100', subnet],
                              capture_output=True, timeout=8)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                # Last resort: ping a few IPs to populate ARP table
                base = '.'.join(subnet.split('.')[:3])
                for i in range(1, 255):
                    try:
                        subprocess.Popen(
                            ['ping', '-c', '1', '-W', '1', f'{base}.{i}'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                        )
                    except:
                        pass
                import time
                time.sleep(2)
    except Exception as e:
        sys.stderr.write(f"ARP refresh failed (non-critical): {e}\n")
    
    return scan_arp_table()


def get_local_subnet():
    """Detect local subnet from default route."""
    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=2)
        for line in result.stdout.split('\n'):
            # Look for default gateway's subnet
            if 'src' in line and not line.startswith('default'):
                parts = line.split()
                if parts[0].count('.') == 3 or '/' in parts[0]:
                    return parts[0]
        # Fallback: get IP and guess /24
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True, timeout=2)
        ip = result.stdout.strip().split()[0]
        base = '.'.join(ip.split('.')[:3])
        return f"{base}.0/24"
    except:
        return "192.168.1.0/24"


if __name__ == "__main__":
    # First try ARP table directly (instant)
    clients = scan_arp_table()
    
    # If ARP table is empty or has very few entries, do a quick nmap scan
    if len(clients) < 2:
        subnet = get_local_subnet()
        sys.stderr.write(f"ARP table has {len(clients)} entries, running quick nmap on {subnet}\n")
        clients = scan_nmap_quick(subnet)
    
    print(json.dumps(clients))
