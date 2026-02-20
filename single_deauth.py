import requests
import time
import random
from datetime import datetime

# Configuration
BACKEND_URL = "http://localhost:8080"
PACKET_ENDPOINT = f"{BACKEND_URL}/api/packets/deauth/batch"
TARGET_AP = "9E:A8:2C:C2:1F:D9"
TARGET_CLIENT = "4C:6F:9C:F4:FA:63"

def generate_single_packet():
    return {
        "src": TARGET_CLIENT,
        "dst": TARGET_AP,
        "bssid": TARGET_AP,
        "reason": 7,
        "signal": random.randint(-60, -40),
        "channel": 1,
        "seq": 1,
        "frameType": "DEAUTH",
        "subtype": 12,
        "timestamp": datetime.now().isoformat(),
        "interfaceName": "wlan1",
        "test": False
    }

def main():
    print("🎯 Sending 1 deauth packet slowly...")
    print(f"   Target AP: {TARGET_AP}")
    print(f"   Source Client: {TARGET_CLIENT}")
    print()
    
    # Generate single packet
    packet = generate_single_packet()
    payload = {"packets": [packet]}
    
    print("📡 Sending packet...")
    try:
        response = requests.post(PACKET_ENDPOINT, json=payload, timeout=10)
        if response.status_code == 200:
            print("✅ Successfully sent 1 deauth packet")
            print(f"   Response: {response.status_code}")
        else:
            print(f"❌ Failed to send packet: {response.status_code} - {response.text}")
            return
    except Exception as e:
        print(f"❌ Error sending packet: {e}")
        return
    
    # Wait a moment for processing
    print("⏳ Waiting 2 seconds for detection...")
    time.sleep(2)
    
    # Check detection status
    print("🔍 Checking detection status...")
    try:
        status_resp = requests.get(f"{BACKEND_URL}/api/detection/status", timeout=5)
        if status_resp.status_code == 200:
            status = status_resp.json()
            server_status = status.get('status', 'SAFE')
            print(f"   Server Status: {server_status}")
            
            if server_status == 'UNSAFE' or status.get('isUnderAttack') == True:
                print("🎉 SUCCESS: Single packet detected!")
            else:
                print("⚠️  Server status is SAFE (single packet may not trigger detection)")
        else:
            print(f"❌ Failed to get status: {status_resp.status_code}")
    except Exception as e:
        print(f"❌ Error checking status: {e}")
    
    # Check recent events
    print("📋 Checking recent events...")
    try:
        events_resp = requests.get(f"{BACKEND_URL}/api/detection/events/recent", timeout=5)
        if events_resp.status_code == 200:
            events = events_resp.json()
            print(f"   Total events in database: {len(events)}")
            
            # Show latest event if exists
            if events:
                latest = events[0]
                print(f"   Latest event:")
                print(f"     ID: {latest.get('eventId')}")
                print(f"     Severity: {latest.get('severity')}")
                print(f"     Attacker: {latest.get('attackerMac')}")
                print(f"     Target: {latest.get('targetBssid')}")
                print(f"     Score: {latest.get('layer1Score')}/100")
                print(f"     Time: {latest.get('detectedAt')}")
            else:
                print("   No events found")
        else:
            print(f"❌ Failed to get events: {events_resp.status_code}")
    except Exception as e:
        print(f"❌ Error checking events: {e}")
    
    print("\n🖥️  Check UI Dashboard for real-time detection details.")

if __name__ == "__main__":
    main()
