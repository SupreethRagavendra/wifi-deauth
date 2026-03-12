# Detection System Fix — Root Cause Analysis & Action Plan

> **Date**: 2026-03-12 | **System**: WiFi Shield 3-Layer Detection Engine  
> **Symptom**: UI dashboard shows all stats at 0 even though the sniffer correctly detects deauth frames.

---

## Architecture Overview

```
PacketSniffer.py  →  DataSender.py  →  PacketController (/api/packets/deauth/batch)
                                              ↓
                                    DetectionService.processBatch()
                                              ↓
                      ┌───────────────────────┼───────────────────────┐
                      ↓                       ↓                       ↓
               Layer 1 (L1)           Layer 2 (L2/ML)           Layer 3 (L3)
              Heuristics             ML Ensemble (4 models)     Physical/Context
              RateAnalyzer           /predict → :5000           RSSI forensics
              SeqValidator                                      Clock skew
              TimeAnomaly
              SessionState
                      └───────────────────────┼───────────────────────┘
                                              ↓
                                    Combined Score (L1×40% + L2×40% + L3×20%)
                                              ↓
                                    Severity → DB (DetectionEvent) → SSE broadcast
                                              ↓
                                     DetectionMonitor.tsx (Frontend)
```

---

## Root Causes Identified

### Bug #1: `useDetectionStats` hook calls `/api/detection/stats` — endpoint DOES NOT EXIST

**File**: `useDetectionStats.ts:66`  
```ts
const res = await pollAxios.get(`${API_URL}/detection/stats`, { headers });
```

**Problem**: `DetectionController.java` has NO `@GetMapping("/stats")` endpoint. This returns **404** silently (the hook catches the error and keeps `defaultStats` with all zeros). The `MLInsightsCard.tsx` sidebar displays Total Predictions, Attack Predictions, Avg Confidence, and Agreement Rate — these all read from the ML service at `:5000/model-stats`, not from the backend.

> **But**: `DetectionMonitor.tsx` **does NOT use** `useDetectionStats` — it only uses `useDetectionStatus` and `useLiveStatus`. So the 5 stat cards (Active Events, Normal, Suspicious, Attacks, Critical) are calculated locally from the `filteredEvents` array. **If events are empty → all stats are 0.**

### Bug #2: Events array stays empty — `/events/recent` returns empty for new sessions

**File**: `DetectionMonitor.tsx:54-98`  
The component fetches from `/api/detection/events/recent` every 3 seconds. This endpoint (in `DetectionController`) calls `layer1Service.getRecentEvents()` → `eventRepository.findTop100ByOrderByDetectedAtDesc()`. This queries the **database**.

**The counting issue**: Each unique attacker MAC gets **one event per 15-second window** (deduplication in `Layer1Service.saveAnomaly`). But the **frontend polls the same `/events/recent` + `/threat-level` every 3 seconds**, which means:
1. During an active attack with continuous deauth packets, the **event count stays stable** (correct behavior).
2. However, the stats counters in the frontend (`stats.normal`, `stats.suspicious`, etc.) are computed from `filteredEvents.length` — which reflects unique detection events, not individual packet counts.

### Bug #3: "Normal disconnect from phone" is NOT counted/shown

**File**: `DetectionService.java:296-298`  
```java
if ("DEAUTH".equalsIgnoreCase(request.getFrameType())) {
    finalScore = Math.max(finalScore, 15); // ← Forces ALL deauth frames to MEDIUM minimum
}
```

**Problem**: The deauth floor of 15 means EVERY deauth frame gets classified as at least `MEDIUM` (Suspicious). There is never a `LOW` severity event — so the "Normal" counter will **ALWAYS be 0**.

Normal phone disconnections send reason code 3 or 8. These should be classified as `LOW` not `MEDIUM`.

### Bug #4: "Counting keeps going until sniffer stops"

**Root cause**: The sniffer sends every captured deauth frame → backend creates/updates Detection Events in DB → frontend polls `/events/recent` which returns all recent events. Since events keep accumulating in the DB (with the 15-second deduplication window), the list grows continuously during an attack. The user sees counts climbing relentlessly.

**What's needed**: The stats should reflect a **time-windowed** view (e.g., "events in last 5 minutes") and events should have a clear "resolved" lifecycle.

### Bug #5: SSE `alert` events fire for EVERY attack packet, inflating in-memory `latestAlert`

**File**: `DetectionService.java:337-340`  
```java
if (mlConfirmsAttack || layer1ConfirmsAttack) {
    triggerAttack(packet, response, mlPrediction, modelAgreement); // fires SSE alert
}
```

And in `triggerAttack()`, `alertService.processAlert(alert)` → `broadcastAlert(alert)` → sends SSE `alert` event. The frontend `useDetectionStatus.ts:138-148` receives each alert and adds it to the events array. This causes the events list to grow with duplicates during a sustained attack.

### Bug #6: ML stats (sidebar) show 0 if ML service hasn't received predictions

The `MLInsightsCard` polls `localhost:5000/model-stats`. Counters (`total_predictions`, `attack_predictions`, etc.) are only incremented when `ml_service.py`'s `/predict` endpoint is called. If the backend's `Layer2Service` fails to reach the ML service, these stay at 0.

---

## Fix Plan

### Fix 1: Add `/api/detection/stats` endpoint (for any hook that calls it)
Add a `@GetMapping("/stats")` to `DetectionController.java` that returns:
```json
{
  "total_packets": <totalPacketCount from DetectionService>,
  "total_events": <count of recent events from DB>,
  "attack_events": <count of CRITICAL+HIGH events>,
  "critical_events": <count of CRITICAL>,
  "suspicious_events": <count of MEDIUM>,
  "current_status": "SAFE|UNSAFE",
  "active_events": <active threats count>,
  "attacks_1hr": <threats in last hour>,
  "ml_models_loaded": <from ML service health>,
  "avg_confidence": <from ML service>,
  "agreement_rate": <from ML service>
}
```

### Fix 2: Fix the deauth floor — allow LOW severity for normal disconnects
In `DetectionService.java`, remove or lower the blanket `Math.max(finalScore, 15)` floor:
- Reason code 3 (Deauthentication because STA leaves) → score floor = 0 (truly normal)
- Reason code 8 (Disassociated because STA leaves) → score floor = 0
- Other reason codes → keep floor at 15 (suspicious by default)

### Fix 3: Time-window the stats display
Frontend stats should reflect a 1-hour window max:
- Use the `/live-status` endpoint data (which already provides `severityBreakdown`) for the stat cards
- Or have `/events/recent` return only the last 1 hour of events

### Fix 4: Deduplicate SSE alert events on frontend
In `DetectionMonitor.tsx`, the `latestAlert` handler already deduplicates by matching MAC + 2s window. But `useDetectionStatus.ts` also receives the same alerts and manages its own state — which the Monitor page doesn't even use for counts. **No code change needed here** — the counts are driven by the `/events/recent` poll, not SSE.

### Fix 5: Add dummy data injection endpoint for testing
Create a `POST /api/detection/inject-test-data` endpoint that inserts synthetic DetectionEvent rows into the database simulating:
- 5 CRITICAL attacks
- 5 HIGH attacks
- 5 MEDIUM (suspicious) events
- 5 LOW (normal disconnect) events
This lets us verify the UI without needing the real sniffer running.

### Fix 6: Verify ML service is reachable from backend
Check `Layer2Service` to ensure it can connect to `localhost:5000/predict`. If not, the ML stats will remain at 0.

---

## Files to Modify

| File | Change |
|------|--------|
| `DetectionController.java` | Add `/stats` endpoint + `/inject-test-data` endpoint |
| `DetectionService.java` | Fix deauth floor (reason-code-aware), improve score calculation |
| `DetectionMonitor.tsx` | Wire stat cards to use `/live-status` `severityBreakdown` instead of local array counting |
| `Layer1Service.java` | Verify `saveAnomaly` saves LOW-severity events (currently saves all events) |
| `useDetectionStats.ts` | Fix to use the correct backend endpoint |

---

## Testing Plan

1. **Backend**: Use `POST /api/detection/inject-test-data` to create sample events
2. **Frontend**: Observe that all stat cards update correctly
3. **Sniffer**: Send real deauth frames → verify events appear and counts are accurate
4. **Normal Disconnect**: Disconnect phone from WiFi → verify it shows as "Normal" (LOW) not "Suspicious"
5. **ML Stats**: Verify the ML sidebar card shows non-zero predictions after injecting data
