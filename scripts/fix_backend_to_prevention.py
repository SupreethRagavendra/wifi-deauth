#!/usr/bin/env python3
"""fix_backend_to_prevention.py — Test backend → prevention engine connection."""
import requests, json, sys, time

BACKEND = "http://localhost:8080"
ENGINE  = "http://localhost:5002"
RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; NC = "\033[0m"

def ok(msg): print(f"  {GREEN}✓{NC} {msg}")
def fail(msg): print(f"  {RED}✗{NC} {msg}")
def warn(msg): print(f"  {YELLOW}⚠{NC} {msg}")

print("═" * 56)
print("Testing Backend → Prevention Engine Connection")
print("═" * 56)

# 1. Backend health
print("\n[1] Backend health check...")
try:
    r = requests.get(f"{BACKEND}/actuator/health", timeout=5)
    ok(f"Backend alive (status={r.status_code})")
except:
    fail("Backend unreachable"); sys.exit(1)

# 2. Prevention engine health
print("\n[2] Prevention engine health...")
try:
    r = requests.get(f"{ENGINE}/health", timeout=5)
    h = r.json()
    ok(f"Engine alive, running={h.get('running')}, processed={h.get('events_processed')}")
except:
    fail("Engine unreachable at port 5002")
    print("  → Run: sudo python3 prevention-engine/level1.py")
    sys.exit(1)

# 3. Backend events → what engine sees
print("\n[3] What does backend return for /api/detection/events/recent?")
try:
    r = requests.get(f"{BACKEND}/api/detection/events/recent", timeout=5)
    events = r.json()
    if isinstance(events, dict):
        events = events.get("data", events.get("content", []))
    print(f"  Returned {len(events)} events")
    
    if len(events) > 0:
        # Show what prevention engine would parse
        ev = events[0]
        ts = ev.get("totalScore", 0) or 0
        mc = ev.get("mlConfidence", 0) or 0
        conf_raw = ev.get("confidence", 0) or 0
        conf = float(conf_raw) * 100 if float(conf_raw) <= 1 else float(conf_raw)
        final_conf = max(conf, ts, mc * 100 if mc <= 1 else mc)
        
        print(f"\n  Latest event field mapping (engine perspective):")
        print(f"    eventId/id  → {ev.get('eventId', ev.get('id', 'MISSING'))}")
        print(f"    attackerMac → {ev.get('attackerMac', ev.get('srcMac', 'MISSING'))}")
        print(f"    targetMac   → {ev.get('targetMac', ev.get('victimMac', 'MISSING'))}")
        print(f"    confidence  → raw={conf_raw}, totalScore={ts}, mlConf={mc}")
        print(f"    EFFECTIVE CONFIDENCE → {final_conf:.1f}%")
        
        if final_conf >= 40:
            ok(f"Would trigger L1 (threshold=40%)")
        if final_conf >= 60:
            ok(f"Would trigger L2 (threshold=60%)")
        if final_conf >= 85:
            ok(f"Would trigger L3 (threshold=85%)")
        if final_conf >= 95:
            ok(f"Would trigger L4 (threshold=95%)")
        if final_conf < 40:
            warn(f"Score {final_conf:.1f}% is BELOW L1 threshold (40%)")
            print("  → Detection scores need to be higher to trigger prevention")
            print("  → Run sustained attack: sudo aireplay-ng --deauth 100 ...")
    else:
        warn("No events in backend — attack may not have been detected yet")
        print("  → Ensure sniffer is running: make run-sniffer CHANNEL=1")
        print("  → Then attack: sudo aireplay-ng --deauth 100 -a 9E:A8:2C:C2:1F:D9 -c 94:65:2D:97:25:87 wlan0mon")
except Exception as e:
    fail(f"Error: {e}")

# 4. Engine internal events
print("\n[4] Prevention engine internal events...")
try:
    r = requests.get(f"{ENGINE}/prevention/events?limit=5", timeout=5)
    pevents = r.json()
    if isinstance(pevents, list):
        print(f"  Engine has {len(pevents)} stored prevention events")
        if len(pevents) > 0:
            ok("Prevention events exist!")
            e = pevents[0]
            print(f"    Last event: confidence={e.get('confidence')}, status={e.get('status')}")
            print(f"    Levels: L1={e.get('level1_fired')} L2={e.get('level2_fired')} L3={e.get('level3_fired')} L4={e.get('level4_fired')}")
        else:
            warn("No prevention events yet — engine hasn't processed any detection events")
    else:
        warn(f"Unexpected response: {str(pevents)[:200]}")
except Exception as e:
    fail(f"Error fetching engine events: {e}")

print("\n" + "═" * 56)
