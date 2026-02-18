import requests
import time
import random
import uuid
from datetime import datetime

# Configuration
BACKEND_URL = "http://localhost:8080"
PACKET_ENDPOINT = f"{BACKEND_URL}/api/packets/deauth/batch"
TARGET_AP = "9E:A8:2C:C2:1F:D9"
TARGET_CLIENT = "4C:6F:9C:F4:FA:63"

def generate_packet(seq):
    return {
        "sourceMac": TARGET_CLIENT,  # Client sends Deauth to AP? Or AP to Client? usually AP->Client or Client->AP
        "dst": TARGET_AP,
        "bssid": TARGET_AP,
        "reason": 7,
        "signal": random.randint(-60, -40), # Strong signal
        "channel": 1,
        "seq": seq,
        "frameType": "DEAUTH",
        "subtype": 12,
        "timestamp": datetime.now().isoformat(),
        "interfaceName": "wlan1",
        "test": False # Not a test packet, treat as real
    }

def main():
    print(f"--> Simulating High-Rate Deauth Attack on {PACKET_ENDPOINT}...")
    
    seq = 0
    total_packets = 1000
    batch_size = 50
    rate = 100 # packets per second target
    
    start_time = time.time()
    
    for i in range(0, total_packets, batch_size):
        batch = []
        for j in range(batch_size):
            batch.append(generate_packet(seq))
            seq += 1
            
        payload = {"packets": batch}
        
        try:
            response = requests.post(PACKET_ENDPOINT, json=payload, timeout=5)
            if response.status_code == 200:
                print(f"✓ Sent batch {i // batch_size + 1}: {len(batch)} packets (Seq {seq})")
            else:
                print(f"✗ Failed batch: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"✗ Error: {e}")
            
        # Limit rate? 
        # If we send 50 packets, and want 100/sec, we sleep 0.5s minus overhead
        elapsed = time.time() - start_time
        target_time = (i + batch_size) / rate
        sleep_time = target_time - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)

    print("\n✓ Simulation Packet Transmission Complete.")
    
    # Check Status
    print("Checking Detection Status...")
    try:
        status_resp = requests.get(f"{BACKEND_URL}/api/detection/status", timeout=5)
        if status_resp.status_code == 200:
            status = status_resp.json()
            server_status = status.get('status', 'SAFE')
            print(f"Server Status: {server_status}")
            
            # Check for UNSAFE status
            if server_status == 'UNSAFE' or status.get('isUnderAttack') == True:
                 print("✓ SUCCESS: Attack Detected!")
            else:
                 print("✗ FAILURE: Server Status is SAFE (Expected UNSAFE)")
        else:
             print(f"✗ Failed to get status: {status_resp.status_code}")
    except Exception as e:
        print(f"✗ Error checking status: {e}")

    print("\nCheck UI Dashboard for details.")

if __name__ == "__main__":
    main()
