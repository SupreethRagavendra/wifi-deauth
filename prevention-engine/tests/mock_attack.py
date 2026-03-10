#!/usr/bin/env python3
"""Mock attack — POST a fake detection event to the prevention engine."""
import sys, requests, json

ENGINE_URL = "http://localhost:5002"


def main():
    confidence = float(sys.argv[1]) if len(sys.argv) > 1 else 75
    payload = {
        "confidence": confidence,
        "attacker_mac": "AA:BB:CC:DD:EE:FF",
        "victim_mac": "4C:6F:9C:F4:FA:63",
    }
    print(f"[MOCK] Triggering defense at {confidence}% confidence...")
    try:
        r = requests.post(f"{ENGINE_URL}/prevention/apply", json=payload, timeout=10)
        print(f"[MOCK] Response ({r.status_code}): {json.dumps(r.json(), indent=2)}")
    except requests.ConnectionError:
        print(f"[MOCK] ❌ Engine not running at {ENGINE_URL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
