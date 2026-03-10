#!/usr/bin/env python3
import subprocess
import json
import sys
import re
import os
import time
import argparse

# Fast method: use nmcli to scan (no monitor mode needed)
def parse_nmcli_scan():
    try:
        result = subprocess.run(
            ['nmcli', '-t', '-f', 'SSID,BSSID,CHAN,SIGNAL,SECURITY', 'device', 'wifi', 'list', '--rescan', 'yes'],
            capture_output=True, text=True, timeout=8
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []

        networks_map = {}
        for line in result.stdout.strip().split('\n'):
            # nmcli -t separates fields with ':'
            # SSID may contain colons (escaped as \:), BSSID is XX:XX:XX:XX:XX:XX
            # Use regex to avoid splitting on escaped colons
            parts = re.split(r'(?<!\\):', line)
            if len(parts) < 5:
                continue
            ssid = parts[0].replace('\\:', ':').strip() or '<Hidden Network>'
            bssid = parts[1].replace('\\:', ':').strip().upper()
            if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', bssid):
                continue
            try:
                channel = int(parts[2].strip()) if parts[2].strip().isdigit() else 0
            except:
                channel = 0
            try:
                rssi = int(parts[3].strip()) if parts[3].strip().lstrip('-').isdigit() else -100
                # nmcli SIGNAL is 0-100, convert to approximate dBm
                if 0 <= rssi <= 100:
                    rssi = max(-100, rssi - 110)
            except:
                rssi = -100
            security = parts[4].strip() if len(parts) > 4 else 'OPEN'
            if not security or security in ('--', ''):
                security = 'OPEN'
            estimated_distance = 'Far (>20m)'
            if rssi > -50: estimated_distance = 'Immediate Proximity (< 1m)'
            elif rssi > -60: estimated_distance = 'Very Close (1-5m)'
            elif rssi > -70: estimated_distance = 'Nearby (5-10m)'
            elif rssi > -80: estimated_distance = 'Mid Range (10-20m)'

            net_obj = {
                'ssid': ssid, 'bssid': bssid, 'rssi': rssi,
                'security': security, 'channel': channel,
                'estimated_distance': estimated_distance
            }
            if ssid not in networks_map or rssi > networks_map[ssid]['rssi']:
                networks_map[ssid] = net_obj

        return list(networks_map.values())
    except Exception as e:
        print(f"nmcli scan failed: {e}", file=sys.stderr)
        return []

# Use airodump-ng to scan for networks using monitor mode interface
def parse_airodump(interface):
    try:
        cmd = ['/usr/sbin/airodump-ng', '-w', '/tmp/dump', '--manufacturer', '--background', '1', interface]
        
        print(f"Executing airodump-ng: {' '.join(cmd)}", file=sys.stderr)
        
        # Run airodump-ng for limited time (5 seconds to get results)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Let it run for 5 seconds to collect data
        time.sleep(5)
        proc.terminate()
        
        # Try to read the CSV output
        csv_files = []
        for f in os.listdir('/tmp'):
            if f.startswith('dump-') and f.endswith('.csv'):
                csv_files.append(f'/tmp/{f}')
        
        # Also check for the main dump file
        if os.path.exists('/tmp/dump-01.csv'):
            csv_files.append('/tmp/dump-01.csv')
        
        networks_map = {}
        
        for csv_file in csv_files:
            try:
                with open(csv_file, 'r') as f:
                    lines = f.readlines()
                    
                in_clients_section = False
                for line in lines:
                    line = line.strip()
                    
                    # Skip header lines and empty lines
                    if not line or line.startswith('#') or 'BSSID' in line:
                        if 'Station MAC' in line:
                            in_clients_section = True
                        continue
                    
                    # Skip clients section
                    if in_clients_section:
                        continue
                    
                    # Parse CSV line
                    parts = line.split(',')
                    if len(parts) < 14:
                        continue
                    
                    bssid = parts[0].strip()
                    # Validate MAC address
                    if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
                        continue
                    
                    # First seen, Last seen, channel, etc.
                    try:
                        channel = int(parts[3].strip()) if parts[3].strip().isdigit() else 0
                    except:
                        channel = 0
                    
                    # RSSI is usually at index 9
                    try:
                        rssi = int(parts[9].strip()) if parts[9].strip() and parts[9].strip() != '-' else -100
                    except:
                        rssi = -100
                    
                    # ESSID (SSID) is at index 13
                    ssid = parts[13].strip() if len(parts) > 13 else ''
                    
                    if not ssid:
                        ssid = '<Hidden Network>'
                    
                    # Determine security type from the capabilities field (index 7)
                    security = 'OPEN'
                    if len(parts) > 7:
                        caps = parts[7].strip().upper()
                        if 'WPA3' in caps:
                            security = 'WPA3'
                        elif 'WPA2' in caps:
                            security = 'WPA2'
                        elif 'WPA' in caps:
                            security = 'WPA'
                        elif 'WEP' in caps:
                            security = 'WEP'
                    
                    # Determine frequency band
                    try:
                        freq = int(parts[4].strip()) if parts[4].strip().isdigit() else 0
                    except:
                        freq = 0
                    
                    freq_band = "Unknown"
                    if 2400 <= freq <= 2500:
                        freq_band = "2.4GHz"
                    elif freq >= 4900:
                        freq_band = "5GHz"
                    
                    # Calculate distance based on RSSI
                    estimated_distance = "Unknown"
                    if rssi > -50:
                        estimated_distance = "Immediate Proximity (< 1m)"
                    elif rssi > -60:
                        estimated_distance = "Very Close (1-5m)"
                    elif rssi > -70:
                        estimated_distance = "Nearby (5-10m)"
                    elif rssi > -80:
                        estimated_distance = "Mid Range (10-20m)"
                    else:
                        estimated_distance = "Far (> 20m)"
                    
                    net_obj = {
                        "ssid": ssid,
                        "bssid": bssid.upper(),
                        "rssi": rssi,
                        "security": security,
                        "channel": channel,
                        "frequency_band": freq_band,
                        "estimated_distance": estimated_distance
                    }
                    
                    # Group by SSID (keep strongest signal)
                    if ssid not in networks_map:
                        networks_map[ssid] = net_obj
                    else:
                        if rssi > networks_map[ssid]['rssi']:
                            networks_map[ssid] = net_obj
                            
            except Exception as e:
                # Try next file
                pass
            finally:
                # Clean up CSV file
                try:
                    os.remove(csv_file)
                except:
                    pass
        
        return list(networks_map.values())
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return []

# Fallback: try using iw dev wlan1 scan
def parse_iw_scan():
    try:
        cmd = ['/usr/sbin/iw', 'dev', 'wlan1', 'scan']
        print(f"Executing iw scan: {' '.join(cmd)}", file=sys.stderr)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            return []
        
        networks_map = {}
        current_bssid = None
        current_ssid = None
        current_channel = 0
        current_rssi = -100
        current_freq = 0
        current_security = 'OPEN'
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            
            if line.startswith('BSS '):
                # Save previous network if exists
                if current_bssid and current_ssid:
                    freq_band = "Unknown"
                    if 2400 <= current_freq <= 2500:
                        freq_band = "2.4GHz"
                    elif current_freq >= 4900:
                        freq_band = "5GHz"
                    
                    estimated_distance = "Unknown"
                    if current_rssi > -50:
                        estimated_distance = "Immediate Proximity (< 1m)"
                    elif current_rssi > -60:
                        estimated_distance = "Very Close (1-5m)"
                    elif current_rssi > -70:
                        estimated_distance = "Nearby (5-10m)"
                    elif current_rssi > -80:
                        estimated_distance = "Mid Range (10-20m)"
                    
                    net_obj = {
                        "ssid": current_ssid,
                        "bssid": current_bssid.upper(),
                        "rssi": current_rssi,
                        "security": current_security,
                        "channel": current_channel,
                        "frequency_band": freq_band,
                        "estimated_distance": estimated_distance
                    }
                    
                    if current_ssid not in networks_map:
                        networks_map[current_ssid] = net_obj
                    else:
                        if current_rssi > networks_map[current_ssid]['rssi']:
                            networks_map[current_ssid] = net_obj
                
                # Parse new BSS
                bssid = line.replace('BSS ', '').split(' ')[0]
                current_bssid = bssid
                current_ssid = None
                current_channel = 0
                current_rssi = -100
                current_freq = 0
                current_security = 'OPEN'
                
            elif line.startswith('SSID: '):
                current_ssid = line.replace('SSID: ', '')
                if not current_ssid:
                    current_ssid = '<Hidden Network>'
                    
            elif line.startswith('freq: '):
                try:
                    current_freq = int(line.replace('freq: ', '').split(' ')[0])
                except:
                    pass
                    
            elif line.startswith('signal: '):
                try:
                    current_rssi = int(float(line.replace('signal: ', '').split(' ')[0]))
                except:
                    pass
                    
            elif 'channel=' in line:
                try:
                    current_channel = int(line.split('channel=')[1].split()[0])
                except:
                    pass
            
            elif 'RSN:' in line or 'WPA:' in line:
                if 'RSN:' in line:
                    current_security = 'WPA2'
                elif 'WPA:' in line:
                    current_security = 'WPA'
                    
            elif 'Authentication suites:' in line or 'Preauthentication' in line:
                if 'WPA3' in line:
                    current_security = 'WPA3'
                    
            elif line.startswith('Privacy:'):
                if 'WEP' in line:
                    current_security = 'WEP'
                elif 'OPEN' in line:
                    current_security = 'OPEN'
        
        # Add last network
        if current_bssid and current_ssid:
            freq_band = "Unknown"
            if 2400 <= current_freq <= 2500:
                freq_band = "2.4GHz"
            elif current_freq >= 4900:
                freq_band = "5GHz"
            
            estimated_distance = "Unknown"
            if current_rssi > -50:
                estimated_distance = "Immediate Proximity (< 1m)"
            elif current_rssi > -60:
                estimated_distance = "Very Close (1-5m)"
            elif current_rssi > -70:
                estimated_distance = "Nearby (5-10m)"
            elif current_rssi > -80:
                estimated_distance = "Mid Range (10-20m)"
            
            net_obj = {
                "ssid": current_ssid,
                "bssid": current_bssid.upper(),
                "rssi": current_rssi,
                "security": current_security,
                "channel": current_channel,
                "frequency_band": freq_band,
                "estimated_distance": estimated_distance
            }
            
            if current_ssid not in networks_map:
                networks_map[current_ssid] = net_obj
            else:
                if current_rssi > networks_map[current_ssid]['rssi']:
                    networks_map[current_ssid] = net_obj
        
        return list(networks_map.values())
        
    except Exception as e:
        print(f"Error in iw scan: {e}", file=sys.stderr)
        return []

def main():
    # Use airodump-ng to scan for networks using monitor mode interface
    # The parsing of args is now inside parse_airodump or global? 
    # Better to parse args in main and pass to parse_airodump
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", default="wlan1", help="Wireless interface in monitor mode")
    args = parser.parse_args()

    # Try nmcli first (fast, no monitor mode required)
    networks = parse_nmcli_scan()

    # Fallback: airodump-ng (requires monitor mode)
    if not networks:
        networks = parse_airodump(args.interface)
    
    # Final fallback: iw scan
    if not networks:
        networks = parse_iw_scan()
    
    # Sort by RSSI descending
    networks.sort(key=lambda x: x['rssi'], reverse=True)
    
    print(json.dumps(networks))

if __name__ == "__main__":
    main()
