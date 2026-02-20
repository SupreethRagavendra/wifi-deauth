#!/usr/bin/env python3
import subprocess
import time
import os
import csv
import json
import argparse
import sys
import re

# Common OUI (Organizationally Unique Identifier) database for device identification
OUI_DATABASE = {
    "94:65:2D": "Apple",
    # "10:B1:DF": "Samsung",  # Removed to rely on API
    "00:1A:11": "Google",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:50:F2": "Microsoft",
    "00:15:5D": "Microsoft",
    "AC:DE:48": "Xiaomi",
    "34:CE:00": "Xiaomi",
    "F4:8C:50": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "64:09:80": "Xiaomi",
    "A0:86:C6": "Murata Manufacturing (WiFi modules)",
    "00:0C:43": "Ralink Technology (WiFi adapters)",
    "00:11:22": "CIMSYS Inc",
    "3C:37:86": "LG Electronics",
    "A4:C3:F0": "LG Electronics",
    "00:1D:09": "Elitegroup Computer Systems",
    "00:24:D7": "Intel Corporate",
    "00:1B:77": "Intel Corporate",
    "D8:9E:F3": "Intel Corporate",
    "AC:22:0B": "Liteon Technology",
    "00:26:B6": "Asustek Computer",
    "2C:56:DC": "Asustek Computer",
    "F8:32:E4": "Asustek Computer",
    "00:1F:C6": "Asustek Computer",
    "70:4D:7B": "Asustek Computer",
    "08:62:66": "Asustek Computer",
    "00:1E:8C": "ASUSTek Computer",
    "00:22:15": "ASUSTek Computer",
    "00:0E:A6": "ASUSTek Computer",
    "00:17:31": "ASUSTek Computer",
    "00:1A:92": "ASUSTek Computer",
    "00:1E:8C": "ASUSTek Computer",
    "00:23:54": "ASUSTek Computer",
    "00:26:18": "ASUSTek Computer",
    "BC:EE:7B": "ASUSTek Computer",
    "D8:50:E6": "ASUSTek Computer",
    "F4:6D:04": "ASUSTek Computer",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:05:69": "VMware",
    "00:1C:14": "VMware",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
}

# Cache for vendor lookups to speed up repeated scans
_vendor_cache = {}

def get_device_name(mac_address):
    """
    Lookup device manufacturer from MAC address using MacVendors API.
    Falls back to local database if API fails.
    Returns manufacturer name or 'Unknown Device' if not found.
    """
    if not mac_address:
        return "Unknown Device"
    
    # Check cache first
    if mac_address in _vendor_cache:
        return _vendor_cache[mac_address]
    
    # Try maclookup.app API V2
    try:
        import urllib.request
        import urllib.error
        
        # User provided API key
        api_key = "01khra19fdej9n3j6p5q47g8m801khra1q5t4w4dmr032teqzjq6l0ueb5pomgk4"
        
        url = f"https://api.maclookup.app/v2/macs/{mac_address}"
        req = urllib.request.Request(url)
        if api_key:
            req.add_header("X-Authentication-Token", api_key) # Header name might vary, but this is common
        req.add_header("Accept", "application/json")
        
        with urllib.request.urlopen(req, timeout=2) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get("success") and data.get("found"):
                vendor = data.get("company", "Unknown Vendor")
                _vendor_cache[mac_address] = vendor
                return vendor
    except Exception as e:
        sys.stderr.write(f"maclookup.app API error for {mac_address}: {str(e)}\n")
    
    # Fallback to local OUI database
    mac_upper = mac_address.upper()
    oui = ':'.join(mac_upper.split(':')[:3])
    
    manufacturer = OUI_DATABASE.get(oui, None)
    if manufacturer:
        return manufacturer
    
    # If not found, try to identify by common patterns
    if mac_upper.startswith(('94:65:2D', 'A4:D1:8C', '00:CD:FE', '3C:15:C2')):
        return "Apple Device"
    # Removed Samsung fallback to rely on API
    
    return "Unknown Device"

def get_ip_from_mac(mac_address):
    """
    Try to get IP address for a MAC address using ARP table and nmap.
    Returns IP address or '-' if not found.
    """
    try:
        # Method 1: Read ARP table
        result = subprocess.run(['arp', '-n'], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            # Parse ARP output
            for line in result.stdout.split('\n'):
                if mac_address.lower() in line.lower():
                    # Extract IP address (first column)
                    parts = line.split()
                    if len(parts) >= 1 and parts[0].count('.') == 3:
                        return parts[0]
        
        # Method 2: Try reading /proc/net/arp (Linux specific)
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f:
                    if mac_address.lower() in line.lower():
                        parts = line.split()
                        if len(parts) >= 1 and parts[0].count('.') == 3:
                            return parts[0]
        except:
            pass
            
    except Exception as e:
        sys.stderr.write(f"Error getting IP for {mac_address}: {str(e)}\n")
    
    return "-"

def scan_clients(interface, bssid, duration=10, channel=None):
    # Use PID to avoid collision if multiple scans happen
    output_prefix = f"/tmp/scan_clients_{os.getpid()}"
    csv_file = f"{output_prefix}-01.csv"
    
    # Clean up previous if any
    if os.path.exists(csv_file):
        try:
            os.remove(csv_file)
        except OSError:
            pass
        
    # Command to run airodump-ng
    # If running as root, no sudo needed. Else sudo.
    cmd_prefix = ["airodump-ng"] if os.geteuid() == 0 else ["sudo", "airodump-ng"]
        
    cmd = cmd_prefix + [
        "--bssid", bssid,
        "--write", output_prefix,
        "--output-format", "csv",
        interface
    ]
    
    if channel:
        cmd += ["--channel", str(channel)]
    
    clients = []
    
    # Log the command being executed for debugging
    sys.stderr.write(f"Executing: {' '.join(cmd)}\n")
    sys.stderr.write(f"Interface: {interface}, BSSID: {bssid}, Duration: {duration}s\n")
    
    try:
        # Start airodump-ng
        # We allow stdout/stderr to pipe through for debugging if needed, or capturing
        # But for now, let's capture stderr to diagnose
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        # Run for specified duration
        time.sleep(duration)
        
        # Terminate process
        proc.terminate()
        try:
            # Capture any error output
            stderr_output = proc.communicate(timeout=1)[1]
            if stderr_output:
                sys.stderr.write(f"airodump-ng stderr: {stderr_output.decode('utf-8', errors='ignore')}\n")
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            
        # Parse CSV if generated
        if os.path.exists(csv_file):
            sys.stderr.write(f"CSV file found: {csv_file}\n")
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            # Find "Station MAC" header section
            start_index = -1
            for i, line in enumerate(lines):
                if line.strip().startswith("Station MAC"):
                    start_index = i
                    break
            
            if start_index != -1 and start_index + 1 < len(lines):
                # Using csv reader for robustness against commas in fields
                # We skip lines until start_index+1
                client_lines = lines[start_index+1:]
                reader = csv.reader(client_lines)
                
                for row in reader:
                    # Row format usually: Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
                    if len(row) < 6: continue
                    
                    client_mac = row[0].strip()
                    power = row[3].strip() 
                    
                    # Ignore if MAC is invalid or empty
                    if not client_mac or client_mac == bssid:
                        continue
                        
                    # Power might be -1 if not close enough
                    try:
                        pwr_val = int(power)
                    except ValueError:
                        pwr_val = -100

                    clients.append({
                        "macAddress": client_mac,
                        "signalStrength": str(pwr_val),
                        "connectionTime": row[1].strip(), 
                        "hostname": get_device_name(client_mac),
                        "ipAddress": get_ip_from_mac(client_mac)
                    })
        else:
            sys.stderr.write(f"CSV file not found: {csv_file}. No data captured from airodump-ng.\n")
                        
    except Exception as e:
        # Log error to stderr for backend to pick up
        sys.stderr.write(f"Error extracting clients: {str(e)}\n")
        
    finally:
        # Cleanup generated files
        for ext in ['-01.csv', '-01.kismet.csv', '-01.kismet.netxml', '-01.log.csv']: 
             f = f"{output_prefix}{ext}"
             if os.path.exists(f):
                 try: 
                     os.remove(f)
                 except OSError: 
                     pass
                     
    return clients

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", default="wlan0mon", help="Wireless interface in monitor mode")
    parser.add_argument("--bssid", required=True, help="Target Access Point BSSID")
    parser.add_argument("--channel", help="Channel of the AP")
    parser.add_argument("--duration", type=int, default=10, help="Scan duration in seconds")
    args = parser.parse_args()
    
    results = scan_clients(args.interface, args.bssid, args.duration, args.channel)
    print(json.dumps(results))
