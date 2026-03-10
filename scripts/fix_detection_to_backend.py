#!/usr/bin/env python3
"""fix_detection_to_backend.py — Test detection → backend pipeline."""
import requests, json, sys
from datetime import datetime

BACKEND = "http://localhost:8080"
RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; NC = "\033[0m"

def ok(msg): print(f"  {GREEN}✓{NC} {msg}")
def fail(msg): print(f"  {RED}✗{NC} {msg}")
def warn(msg): print(f"  {YELLOW}⚠{NC} {msg}")

print("═" * 56)
print("Testing Detection → Backend Connection")
print("═" * 56)

# Test 1: Can we reach backend?
print("\n[Test 1] Backend health...")
try:
    r = requests.get(f"{BACKEND}/actuator/health", timeout=5)
    if r.status_code == 200:
        ok("Backend is running")
    else:
        fail(f"Backend returned {r.status_code}")
        sys.exit(1)
except requests.ConnectionError:
    fail("Cannot connect to backend on port 8080")
    print("  → Start backend: make run-backend")
    sys.exit(1)

# Test 2: Fetch existing events
print("\n[Test 2] Checking existing detection events...")
try:
    r = requests.get(f"{BACKEND}/api/detection/events/recent", timeout=5)
    events = r.json()
    if isinstance(events, dict):
        events = events.get("data", events.get("content", []))
    ok(f"Got {len(events)} detection events")
    if len(events) > 0:
        latest = events[0]
        print(f"  Latest event:")
        print(f"    eventId:    {latest.get('eventId')}")
        print(f"    attackerMac: {latest.get('attackerMac')}")
        print(f"    targetMac:   {latest.get('targetMac')}")
        print(f"    totalScore:  {latest.get('totalScore')}")
        print(f"    mlConfidence:{latest.get('mlConfidence')}")
        print(f"    severity:    {latest.get('severity')}")
        print(f"    detectedAt:  {latest.get('detectedAt')}")
        
        ts = latest.get("totalScore", 0) or 0
        mc = latest.get("mlConfidence", 0) or 0
        confidence = max(ts, mc * 100 if mc <= 1 else mc)
        if confidence >= 40:
            ok(f"Confidence={confidence:.1f}% → Prevention WOULD trigger (≥40%)")
        else:
            warn(f"Confidence={confidence:.1f}% → Below L1 threshold (need ≥40%)")
    else:
        warn("No events in backend. Need to run sniffer + attack first")
except Exception as e:
    fail(f"Error: {e}")

# Test 3: Can prevention engine fetch from backend?
print("\n[Test 3] Prevention engine polling test...")
try:
    r = requests.get("http://localhost:5002/health", timeout=5)
    health = r.json()
    ok(f"Engine running={health.get('running')}, processed={health.get('events_processed')}")
    ok(f"Last poll: {health.get('last_poll', 'never')}")
except requests.ConnectionError:
    fail("Prevention engine NOT running on port 5002")
    print("  → Start: sudo python3 prevention-engine/level1.py")

# Test 4: Manual trigger test
print("\n[Test 4] Manual trigger test via mock attack...")
try:
    payload = {
        "confidence": 75,
        "attacker_mac": "AA:BB:CC:DD:EE:FF",
        "victim_mac": "94:65:2D:97:25:87",
    }
    r = requests.post("http://localhost:5002/prevention/apply", json=payload, timeout=10)
    result = r.json()
    if result.get("queued"):
        ok(f"Mock attack queued at {result.get('confidence')}% confidence")
        print("  → Check dashboard in ~3 seconds for the event")
    else:
        fail(f"Unexpected response: {result}")
except requests.ConnectionError:
    fail("Cannot reach prevention engine")
    print("  → Start: sudo python3 prevention-engine/level1.py")
except Exception as e:
    fail(f"Error: {e}")

print("\n" + "═" * 56)
