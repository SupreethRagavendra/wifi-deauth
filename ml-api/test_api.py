
import requests
import json

# Sample Attack Data (Should trigger ATTACK)
attack_payload = {
    # frame_rate: 500
    # seq_variance: 500
    # rssi: -30
    # etc...
    "features": [500.0, 500.0, 0.002, 0.001, -30, 20.0, 14, 6, 10, 7, 100, 10, 5000, 6]
}

# Normal Data (Should trigger NORMAL)
normal_payload = {
    "features": [1.0, 5.0, 1.0, 0.1, -60, 2.0, 10, 2, 1, 1, 3600, 600, 2000, 1]
}

def test_api(payload, name):
    print(f"\n🧪 Testing: {name}")
    try:
        response = requests.post("http://localhost:5000/predict", json=payload)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Status: {response.status_code}")
            print(f"🔍 Verdict: {result['verdict']}")
            print(f"📊 Confidence: {result['confidence']}%")
            print(f"ℹ️ Components: {json.dumps(result['details'], indent=2)}")
        else:
            print(f"❌ Error: {response.text}")
    except Exception as e:
        print(f"❌ Connection Failed: {str(e)}")

if __name__ == "__main__":
    print("🚀 Starting API test...")
    test_api(attack_payload, "Obvious Attack (High Rate)")
    test_api(normal_payload, "Normal User (Low Rate)")
