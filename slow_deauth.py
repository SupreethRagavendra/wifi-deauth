import requests
import time
import random
from datetime import datetime

# Configuration
BACKEND_URL = "http://localhost:8080"
PACKET_ENDPOINT = f"{BACKEND_URL}/api/packets/deauth/batch"
TARGET_AP = "9E:A8:2C:C2:1F:D9"
TARGET_CLIENT = "4C:6F:9C:F4:FA:63"

def generate_packet(seq):
    return {
        "src": TARGET_CLIENT,
        "dst": TARGET_AP,
        "bssid": TARGET_AP,
        "reason": 7,
        "signal": random.randint(-60, -40),
        "channel": 1,
        "seq": seq,
        "frameType": "DEAUTH",
        "subtype": 12,
        "timestamp": datetime.now().isoformat(),
        "interfaceName": "wlan1",
        "test": False
    }

def main():
    print("🎯 Sending deauth packets slowly (1 packet every 2 seconds)...")
    print(f"   Target AP: {TARGET_AP}")
    print(f"   Source Client: {TARGET_CLIENT}")
    print()
    
    num_packets = 5
    seq = 1
    
    for i in range(num_packets):
        print(f"📡 Sending packet {i+1}/{num_packets}...")
        
        # Generate single packet
        packet = generate_packet(seq)
        payload = {"packets": [packet]}
        
        try:
            response = requests.post(PACKET_ENDPOINT, json=payload, timeout=10)
            if response.status_code == 200:
                print(f"   ✅ Packet {i+1} sent successfully")
            else:
                print(f"   ❌ Failed packet {i+1}: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"   ❌ Error sending packet {i+1}: {e}")
        
        seq += 1
        
        # Wait 2 seconds between packets (slow transmission)
        if i < num_packets - 1:  # Don't wait after last packet
            print("   ⏳ Waiting 2 seconds...")
            time.sleep(2)
    
    print("\n⏳ Waiting 3 seconds for detection processing...")
    time.sleep(3)
    
    # Check detection status
    print("🔍 Checking detection status...")
    try:
        status_resp = requests.get(f"{BACKEND_URL}/api/detection/status", timeout=5)
        if status_resp.status_code == 200:
            status = status_resp.json()
            server_status = status.get('status', 'SAFE')
            under_attack = status.get('isUnderAttack', False)
            print(f"   Server Status: {server_status}")
            print(f"   Under Attack: {under_attack}")
            
            if server_status == 'UNSAFE' or under_attack:
                print("🎉 SUCCESS: Attack detected!")
            else:
                print("⚠️  Server status is SAFE")
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
            
            # Show latest events
            if events:
                print("   Latest events:")
                for idx, event in enumerate(events[:3]):  # Show top 3
                    print(f"     Event {idx+1}:")
                    print(f"       ID: {event.get('eventId')}")
                    print(f"       Severity: {event.get('severity')}")
                    print(f"       Attacker: {event.get('attackerMac')}")
                    print(f"       Target: {event.get('targetBssid')}")
                    print(f"       Score: {event.get('layer1Score')}/100")
                    print(f"       Time: {event.get('detectedAt')}")
                    print()
            else:
                print("   No events found")
        else:
            print(f"❌ Failed to get events: {events_resp.status_code}")
    except Exception as e:
        print(f"❌ Error checking events: {e}")
    
    print("🖥️  Check UI Dashboard for real-time detection details.")

if __name__ == "__main__":
    main()
