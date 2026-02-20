#!/usr/bin/env python3
import urllib.request
import urllib.error
import json
import sys

def lookup_mac(mac):
    print(f"Checking MAC: {mac}")
    
    # Try maclookup.app API V2
    api_url = f"https://api.maclookup.app/v2/macs/{mac}"
    api_key = "01khra19fdej9n3j6p5q47g8m801khra1q5t4w4dmr032teqzjq6l0ueb5pomgk4"
    
    try:
        req = urllib.request.Request(api_url)
        req.add_header("X-Authentication-Token", api_key)
        req.add_header("Accept", "application/json")
        
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get("success") and data.get("found"):
                vendor = data.get("company", "Unknown Vendor")
                print(f"API Result: {vendor}")
                return vendor
            else:
                print(f"API Result: Not Found (Success: {data.get('success')})")
    except Exception as e:
        print(f"API Error: {e}")
    
    return None

if __name__ == "__main__":
    mac_to_check = sys.argv[1] if len(sys.argv) > 1 else "10:B1:DF:51:B2:89"
    lookup_mac(mac_to_check)
