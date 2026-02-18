#!/usr/bin/env python3
import subprocess
import json
import sys
import re

def parse_nmcli():
    try:
        # Run nmcli command with FREQ included to detect band
        # -t: terse (colon separated)
        # -f: fields
        # --rescan yes: Force fresh scan as requested
        cmd = ['nmcli', '-t', '-f', 'BSSID,SSID,SIGNAL,SECURITY,CHAN,FREQ', 'dev', 'wifi', 'list', '--rescan', 'yes']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return []

        networks_map = {} # Key by BSSID to avoid duplicates if any, but actually we want by SSID strongest?
        # The user asked: "Group duplicate SSIDs by keeping only the strongest signal."
        
        for line in result.stdout.split('\n'):
            if not line:
                continue
            
            parts = split_terse(line)
            if len(parts) < 6:
                continue
                
            bssid = parts[0].replace('\\:', ':')
            # Validate Mac Address
            if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
                continue
                
            ssid = parts[1]
            try:
                signal = int(parts[2])
                rssi = (signal // 2) - 100
            except:
                rssi = -100

            security_raw = parts[3]
            try:
                chan = int(parts[4])
            except:
                chan = 0
            
            freq_str = parts[5].replace(' MHz', '')
            try:
                freq = int(freq_str)
            except:
                freq = 0
            
            # Frequency Band
            freq_band = "Unknown"
            if 2400 <= freq <= 2500:
                freq_band = "2.4GHz"
            elif freq >= 4900:
                freq_band = "5GHz"

            # Normalize security strictly
            security = "OPEN" # Default to OPEN if empty or dashes
            
            # nmcli separates multiple securities with space
            sec_upper = security_raw.upper()
            if not sec_upper or sec_upper == "--" or sec_upper == "":
                security = "OPEN"
            elif "802.1X" in sec_upper:
                security = "WPA2_ENTERPRISE"
            elif "WPA3" in sec_upper and "SAE" in sec_upper:
                security = "WPA3"
            elif "WPA2" in sec_upper:
                 security = "WPA2"
            elif "WPA" in sec_upper:
                 security = "WPA"
            elif "WEP" in sec_upper:
                 security = "WEP"
            elif "OWE" in sec_upper:
                 security = "WPA3_OWE"
            
            # Handle hidden
            if not ssid or ssid == "--":
                ssid = "<Hidden Network>"
            
            # Calculate distance
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
                "bssid": bssid,
                "rssi": rssi,
                "security": security,
                "channel": chan,
                "frequency_band": freq_band,
                "estimated_distance": estimated_distance
            }
            
            # Grouping Logic:
            # We need to return specific BSSIDs but user said "Group duplicate SSIDs by keeping only the strongest signal"
            # If we group, we lose BSSID info of the other (weaker) APs.
            # Usually for a scanner used for registration, showing unique SSIDs is better.
            
            if ssid not in networks_map:
                networks_map[ssid] = net_obj
            else:
                if rssi > networks_map[ssid]['rssi']:
                    networks_map[ssid] = net_obj
                    
        return list(networks_map.values())
        
    except Exception as e:
        return []

def split_terse(line):
    parts = []
    current = ""
    i = 0
    while i < len(line):
        char = line[i]
        if char == '\\':
            if i + 1 < len(line):
                current += line[i+1]
                i += 2
                continue
        elif char == ':':
            parts.append(current)
            current = ""
            i += 1
            continue
        
        current += char
        i += 1
    parts.append(current)
    return parts

def main():
    networks = parse_nmcli()
    
    # Sort by RSSI desc
    networks.sort(key=lambda x: x['rssi'], reverse=True)
    
    print(json.dumps(networks))

if __name__ == "__main__":
    main()
