# Wi-Fi Deauth Detection System - Dashboard UI Fix

## Root Cause Analysis

The dashboard was not updating during attacks due to **3 critical issues**:

### Issue 1: Database Connection Failure
- **Problem**: Backend crashes on startup with `UnknownHostException: mysql-17ccfa7c-supreethvennila-ef7e.d.aivencloud.com`
- **Cause**: When `wlan0` is used for packet capture (monitor mode), internet connectivity is lost, preventing connection to the cloud MySQL database
- **Solution**: Created H2 in-memory database profile that doesn't require external database

### Issue 2: API Endpoint Mismatch  
- **Problem**: Frontend calls `GET /api/detection/events/recent` but endpoint didn't exist
- **Cause**: Frontend was built expecting an endpoint that wasn't implemented in backend
- **Solution**: Added the missing `/events/recent` endpoint to `DetectionController.java`

### Issue 3: Hardcoded Detection Thresholds
- **Problem**: Detection thresholds were hardcoded (10 packets in 5 seconds), ignoring `application.yml` config
- **Cause**: `DetectionService.java` used `private static final` instead of `@Value` annotations
- **Solution**: Changed to use `@Value` annotations so config changes take effect

---

## Files Modified

1. **DetectionController.java** - Added `/events/recent` endpoint
2. **DetectionService.java** - Uses config values instead of hardcoded constants
3. **application-h2.yml** (NEW) - H2 in-memory database profile
4. **Makefile** - Added `run-backend-h2` and `clean-force` targets

---

## Quick Start Instructions

### Step 1: Clean the build (required due to permission issues)
```bash
make clean-force
```

### Step 2: Start Backend with H2 Database (no internet required)
```bash
make run-backend-h2
```

### Step 3: Start Frontend (in another terminal)
```bash
make run-frontend
```

### Step 4: Start Packet Sniffer (in another terminal)
```bash
make run-sniffer
```

### Step 5: Launch Real Attack (in another terminal)
```bash
make real-attack
```

### Step 6: Open Dashboard
```
http://localhost:3000/detection-monitor
```
(or the main Dashboard page if Detection Monitor is integrated there)

---

## Expected Behavior After Fix

1. ✅ Backend starts successfully (no database connection errors)
2. ✅ Packet sniffer captures deauth frames on wlan1
3. ✅ Backend receives packets via `POST /api/packets/deauth/batch`
4. ✅ Detection threshold triggers after 5+ packets in 10 seconds
5. ✅ Alert is created and stored in memory
6. ✅ `GET /api/detection/events/recent` returns detection events
7. ✅ Frontend polls every 3 seconds and displays events
8. ✅ Dashboard shows "ATTACK DETECTED" with RED indicator

---

## Testing Commands

### Test Backend Status Endpoint
```bash
curl http://localhost:8080/api/detection/status
```
Expected response:
```json
{"status":"SAFE","isUnderAttack":false,"totalPackets":0}
```

### Test Events Endpoint
```bash
curl http://localhost:8080/api/detection/events/recent
```
Expected response (during attack):
```json
[
  {
    "eventId": 1,
    "attackerMac": "94:65:2D:97:25:87",
    "targetBssid": "9E:A8:2C:C2:1F:D9",
    "layer1Score": 85,
    "severity": "HIGH",
    "detectedAt": "2026-02-09T05:00:00.000Z",
    "type": "DEAUTH_FLOOD",
    "packetCount": 64
  }
]
```

### Simulate Attack (no WiFi adapter needed)
```bash
make attack-test
```

---

## Architecture Summary

```
┌─────────────────┐    Deauth    ┌──────────────┐
│  Attacker       │ ──────────►  │   wlan1      │
│  (aireplay-ng)  │   frames     │  (monitor)   │
└─────────────────┘              └──────┬───────┘
                                        │ Scapy capture
                                        ▼
                              ┌───────────────────┐
                              │  Python Sniffer   │
                              │  (main.py)        │
                              └─────────┬─────────┘
                                        │ HTTP POST /api/packets/deauth/batch
                                        ▼
                              ┌───────────────────┐
                              │  Spring Backend   │
                              │  DetectionService │
                              │  (H2 in-memory)   │
                              └─────────┬─────────┘
                                        │ Threshold trigger → Alert
                                        ▼
                              ┌───────────────────┐
                              │  AlertService     │
                              │  (in-memory list) │
                              └─────────┬─────────┘
                                        │ GET /api/detection/events/recent
                                        ▼
                              ┌───────────────────┐
                              │  React Dashboard  │
                              │  (polls every 3s) │
                              └───────────────────┘
```

---

## Configuration Reference

### Detection Thresholds (application.yml)
```yaml
detection:
  attack-threshold: 5          # packets to trigger attack
  rate-analyzer:
    window-seconds: 10         # time window for counting
```

### Network Configuration
```yaml
detection:
  monitor:
    interface: wlan1           # packet capture interface
```

---

## Troubleshooting

### "Communications link failure" error
→ Use `make run-backend-h2` instead of `make run-backend`

### Permission denied when cleaning
→ Run `make clean-force` (uses sudo)

### Dashboard shows "No threats detected"
→ Check if sniffer is running: `make run-sniffer`
→ Check if attack is running: `make real-attack`

### wlan1 not capturing
→ Verify monitor mode: `iwconfig wlan1`
→ Check channel: `iwconfig wlan1 channel 1`

---

## Summary

The fix ensures the dashboard updates in real-time by:
1. Removing the database dependency for demo mode (H2)
2. Adding the missing API endpoint the frontend expects
3. Making detection thresholds configurable
4. Wrapping database operations in try-catch so detection works even if DB fails
