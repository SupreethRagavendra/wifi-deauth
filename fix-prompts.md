# Fix Prompts — WiFi Deauth Detection System

> Each prompt below is a self-contained instruction you can hand to an AI assistant (or follow yourself) to fix a specific issue. They are ordered by priority.

---

## P0-1: Fix "System Shows Safe During Attacks"

**Problem**: `isCurrentlyUnderAttack()` in `Layer1Service.java` only considers CRITICAL/HIGH events in the last 15 seconds. MEDIUM-severity events (which are common during moderate attacks) are ignored, so the system shows "Safe" even when attacks are happening.

**File**: `wifi-security-backend/src/main/java/com/wifi/security/service/layer1/Layer1Service.java`

**Prompt**:
```
In Layer1Service.java, fix the `isCurrentlyUnderAttack()` method (around line 426-438).

Currently it checks:
    .anyMatch(e -> e.getSeverity().name().equals("CRITICAL") || e.getSeverity().name().equals("HIGH"))

Change it to ALSO include MEDIUM severity:
    .anyMatch(e -> e.getSeverity().name().equals("CRITICAL") || 
                   e.getSeverity().name().equals("HIGH") ||
                   e.getSeverity().name().equals("MEDIUM"))

This ensures the system correctly shows "UNSAFE" when moderate attacks are occurring,
not just full-blown critical ones.
```

---

## P0-2: Fix "Attacks Detected (1hr)" Count Not Increasing

**Problem**: The `threatsLastHour` value comes from `DetectionController.getLiveStatus()` which queries DB events. But `saveAnomaly()` in `Layer1Service` skips LOW events entirely. If many events are scored as LOW by L1 alone (before ML runs), they never get persisted, so the count stays low. Additionally, the `getLiveStatus()` query may only count specific severities.

**File**: `wifi-security-backend/src/main/java/com/wifi/security/controller/DetectionController.java`

**Prompt**:
```
In DetectionController.java, find the `getLiveStatus()` method (the GET /live-status endpoint).

Check how `threatsLastHour` is calculated. It should count ALL detection events 
with severity MEDIUM, HIGH, or CRITICAL from the last 60 minutes. 

The query should be:
    LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);
    List<DetectionEvent> recentEvents = layer1Service.getRecentEvents()
        .stream()
        .filter(e -> e.getDetectedAt().isAfter(oneHourAgo))
        .filter(e -> !e.getSeverity().name().equals("LOW"))
        .collect(Collectors.toList());
    int threatsLastHour = recentEvents.size();

Also verify that `activeThreats` counts events from the last 30 seconds (not 15).
Make sure the response map includes:
    - "systemStatus": underAttack ? "UNDER_ATTACK" : "SAFE"
    - "activeThreats": count of events in last 30 seconds
    - "threatsLastHour": count of non-LOW events in last 60 minutes
    - "underAttack": boolean from layer1Service.isCurrentlyUnderAttack()

Do NOT change any detection logic — only fix the counting/query.
```

---

## P0-3: Fix SSE Alert → DetectionMonitor Event Mapping

**Problem**: In `DetectionService.triggerAttack()` line 291, `alert.setPacketCount(response.getCombinedScore())` sets the packet count to the **score** value. Then in `DetectionMonitor.tsx`, `latestAlert.packetCount` is used as `layer1Score` for the synthetic event. This means the score shown on the monitor is actually the combined score being displayed as a packet count, causing confusion.

**Files**: 
- `wifi-security-backend/src/main/java/com/wifi/security/service/DetectionService.java`
- `wifi-security-frontend/src/pages/DetectionMonitor.tsx`

**Prompt**:
```
Fix the packet count vs score confusion in the alert pipeline:

1. In DetectionService.java `triggerAttack()` method (around line 291):
   Change:
       alert.setPacketCount(response.getCombinedScore());
   To:
       alert.setPacketCount(
           response.getAnalyzerScores() != null 
               ? response.getAnalyzerScores().getRateAnalyzerScore() 
               : 0);
       alert.setScore(response.getCombinedScore());
   
   Do the same fix in `broadcastMinorEvent()` (around line 319).

2. In AlertDTO.java, make sure there is a `score` field (int) if it doesn't exist already.
   It should have: type, severity, message, attackerMac, targetBssid, targetMac,
   packetCount, score, signal, channel, timestamp, layer2Score, layer3Score,
   mlConfidence, mlPrediction, modelAgreement

3. In DetectionMonitor.tsx, fix the SSE event mapping (around line 85-101):
   Change:
       layer1Score: latestAlert.packetCount,
   To:
       layer1Score: latestAlert.score || latestAlert.packetCount || 0,

This ensures the detection monitor shows the actual combined score, not the rate 
analyzer count.
```

---

## P1-1: Reconcile Dual Prevention Systems

**Problem**: Java backend and Python ML API maintain **separate** blocklists. A MAC blocked by `Layer1Service.saveAnomaly()` only updates Java's in-memory blocklist, NOT `iptables`. A MAC blocked by the ML API's `PreventionEngine` updates `iptables` but the Java blocklist doesn't know unless `/prevention/notify` is called.

**Files**:
- `ml-api/prevention_engine.py`
- `wifi-security-backend/src/main/java/com/wifi/security/controller/PreventionController.java`

**Prompt**:
```
Reconcile the dual prevention systems so the Java backend is the single source of truth 
for the frontend, and the Python prevention engine handles actual iptables blocking.

1. In prevention_engine.py, after every block/unblock action in `_level2_temp_block()`, 
   `_level3_full_block()`, and `_unblock_mac()`, add an HTTP POST to notify the 
   Java backend:

   import requests
   BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8080/api")
   
   def _notify_backend(self, mac, action, level, confidence, duration=None):
       try:
           requests.post(f"{BACKEND_URL}/prevention/notify", json={
               "mac": mac,
               "action": action,
               "level": level,
               "confidence": confidence,
               "duration": duration or 0
           }, timeout=2)
       except Exception as e:
           logger.warning(f"Failed to notify backend: {e}")

   Call this at the end of each block method:
   - _level2_temp_block: self._notify_backend(mac, "TEMP_BLOCK", 2, confidence, minutes*60*1000)
   - _level3_full_block: self._notify_backend(mac, "FULL_BLOCK", 3, confidence)
   - _unblock_mac: self._notify_backend(mac, "UNBLOCK", 0, 0)

2. In PreventionController.java `notifyPreventionAction()`, ensure it correctly handles
   all three action types (TEMP_BLOCK, FULL_BLOCK, UNBLOCK) and updates the blocklist.
   This should already work based on existing code, but verify UNBLOCK removes from
   the ConcurrentHashMap.

Do NOT remove iptables blocking from the Python side — that's the actual network-level
enforcement. The Java side is for frontend visibility.
```

---

## P1-2: Fix `updateWithMlScores()` Race Condition

**Problem**: When multiple deauth packets from the same MAC arrive rapidly, `updateWithMlScores()` finds the "most recent" event via `findTop100ByOrderByDetectedAtDesc()` and filters by MAC. If two events are saved within the same millisecond, it may update the wrong one.

**File**: `wifi-security-backend/src/main/java/com/wifi/security/service/layer1/Layer1Service.java`

**Prompt**:
```
Fix the race condition in Layer1Service.updateWithMlScores() (around line 445-483).

Instead of finding the event by source MAC from the last 100 events, pass the event 
ID directly from DetectionService.

1. Change the signature of updateWithMlScores to accept a Long eventId:
   public void updateWithMlScores(Long eventId, String sourceMac, int mlScore, 
       double mlConfidence, String mlPrediction, String modelAgreement, 
       Integer layer3Score, String layer3Notes, int finalScore)

2. Change the implementation to use eventId if provided:
   if (eventId != null) {
       eventRepository.findById(eventId).ifPresent(event -> {
           // update fields...
           eventRepository.save(event);
       });
   } else {
       // fallback to existing MAC-based lookup
   }

3. In Layer1Service.saveAnomaly(), return the saved event's ID:
   Change return type from void to Long
   Return savedEvent.getEventId()

4. In DetectionService.analyzePayload(), capture the event ID from saveAnomaly 
   (called inside Layer1Service.analyze()) and pass it to updateWithMlScores.
   
   Note: saveAnomaly is called inside analyze() → so analyze() needs to return
   the event ID. Add it to DetectionResponse as a field, or store it in a separate 
   return value. The simplest approach: add `lastSavedEventId` field to 
   DetectionResponse.
```

---

## P1-3: Fix TINYINT UNSIGNED Overflow Risk

**Problem**: `layer1_score`, `layer2_score`, `layer3_score`, and `total_score` columns use `TINYINT UNSIGNED` (max 255). While current scores shouldn't exceed this, the weighted final score formula *can* in edge cases. This would cause silent truncation or errors.

**File**: `wifi-security-backend/src/main/java/com/wifi/security/entity/detection/DetectionEvent.java`

**Prompt**:
```
In DetectionEvent.java, change the column definitions for score fields from 
TINYINT UNSIGNED to SMALLINT UNSIGNED to prevent overflow:

Change these 4 fields:
    @Column(name = "layer1_score", nullable = false, columnDefinition = "TINYINT UNSIGNED")
    @Column(name = "layer2_score", nullable = false, columnDefinition = "TINYINT UNSIGNED")
    @Column(name = "layer3_score", nullable = false, columnDefinition = "TINYINT UNSIGNED")
    @Column(name = "total_score", nullable = false, columnDefinition = "TINYINT UNSIGNED")

To:
    @Column(name = "layer1_score", nullable = false, columnDefinition = "SMALLINT UNSIGNED")
    @Column(name = "layer2_score", nullable = false, columnDefinition = "SMALLINT UNSIGNED")
    @Column(name = "layer3_score", nullable = false, columnDefinition = "SMALLINT UNSIGNED")
    @Column(name = "total_score", nullable = false, columnDefinition = "SMALLINT UNSIGNED")

After changing, you need to run the backend with `spring.jpa.hibernate.ddl-auto=update` 
or manually ALTER the MySQL table:
    ALTER TABLE detection_events 
        MODIFY COLUMN layer1_score SMALLINT UNSIGNED NOT NULL DEFAULT 0,
        MODIFY COLUMN layer2_score SMALLINT UNSIGNED NOT NULL DEFAULT 0,
        MODIFY COLUMN layer3_score SMALLINT UNSIGNED NOT NULL DEFAULT 0,
        MODIFY COLUMN total_score SMALLINT UNSIGNED NOT NULL DEFAULT 0;
```

---

## P2-1: Unify UI Design Language

**Problem**: `PreventionDashboard.tsx` uses `slate` colors, gradient headers, `font-black`, and custom `glow-*` classes. `AdminDashboard.tsx` and `DetectionMonitor.tsx` use `gray-50`, `font-bold`, and blue-600 primary. The pages look like they belong to different apps.

**File**: `wifi-security-frontend/src/pages/PreventionDashboard.tsx`

**Prompt**:
```
Update PreventionDashboard.tsx to match the design language of AdminDashboard.tsx 
and DetectionMonitor.tsx. Specifically:

1. Change the root background from `bg-slate-50` to `bg-gray-50`
2. Replace the header:
   - Remove the gradient icon div (`bg-gradient-to-br from-indigo-600 to-blue-700`)
   - Use the same header as AdminDashboard: simple `bg-white border-b border-gray-200`
     with a `bg-blue-600` rounded-lg icon
   - Change title from `font-black` to `font-bold`
   - Use the same nav layout: links in a row (Admin Dashboard, Monitor, Logout)
   
3. Replace all `slate-*` colors with `gray-*` equivalents:
   - `bg-slate-50` → `bg-gray-50`
   - `text-slate-900` → `text-gray-900`
   - `text-slate-500` → `text-gray-500`
   - `border-slate-200` → `border-gray-200`
   - `bg-slate-100` → `bg-gray-100`
   
4. Remove custom `glow-*` classes (glow-primary, glow-success, glow-danger) — 
   they may not exist in the CSS and would cause no visual effect anyway.

5. Change card styling from `rounded-2xl` to `rounded-xl` to match other pages.

6. Keep the 4-level pipeline visualization as-is — that's unique to this page and 
   should stay.

7. Keep the color-coded blocked MAC rows (red for L3/L4, orange for L2) — those are
   functional, not decorative.

Do NOT change any logic, state management, SSE connections, or API calls.
Only change visual styling to match the gray/blue/white theme of the other pages.
```

---

## P2-2: Add Back-Navigation to DetectionMonitor

**Problem**: DetectionMonitor header has links to "Prevention" and "Logout" but no link back to "Admin Dashboard". Users have to use browser back button.

**File**: `wifi-security-frontend/src/pages/DetectionMonitor.tsx`

**Prompt**:
```
In DetectionMonitor.tsx, add an "Admin Dashboard" navigation link in the header 
(around line 166-183).

Add this button before the "Prevention" button:
    <button
        onClick={() => navigate('/admin/dashboard')}
        className="text-sm font-medium text-blue-600 hover:text-blue-800"
    >
        Admin Dashboard
    </button>

This matches the navigation pattern in AdminDashboard.tsx which has links to both 
Detection Monitor and Prevention.
```

---

## P2-3: Fix Heuristics Breakdown to Show Real Sub-Scores

**Problem**: The expanded event detail in `DetectionMonitor.tsx` shows 4 progress bars (Rate, Sequence, Time, Session) but they're ALL derived from the same `layer1Score` using fixed multipliers. This means every event shows the same proportional breakdown regardless of which analyzer actually triggered.

**Files**:
- `wifi-security-backend/src/main/java/com/wifi/security/entity/detection/DetectionEvent.java`
- `wifi-security-backend/src/main/java/com/wifi/security/service/layer1/Layer1Service.java`  
- `wifi-security-frontend/src/types/index.ts`
- `wifi-security-frontend/src/pages/DetectionMonitor.tsx`

**Prompt**:
```
Store and display actual per-analyzer scores from Layer 1 instead of deriving them.

1. In DetectionEvent.java, add 4 new fields:
   @Column(name = "rate_analyzer_score", columnDefinition = "TINYINT UNSIGNED DEFAULT 0")
   private Integer rateAnalyzerScore;
   
   @Column(name = "seq_validator_score", columnDefinition = "TINYINT UNSIGNED DEFAULT 0")
   private Integer seqValidatorScore;
   
   @Column(name = "time_anomaly_score", columnDefinition = "TINYINT UNSIGNED DEFAULT 0")
   private Integer timeAnomalyScore;
   
   @Column(name = "session_state_score", columnDefinition = "TINYINT UNSIGNED DEFAULT 0")
   private Integer sessionStateScore;

2. In Layer1Service.saveAnomaly(), populate these from the DetectionResponse:
   .rateAnalyzerScore(response.getAnalyzerScores() != null ? 
       response.getAnalyzerScores().getRateAnalyzerScore() : 0)
   (same for seq, time, session)

3. In frontend types/index.ts DetectionEvent interface, add:
   rateAnalyzerScore?: number;
   seqValidatorScore?: number;
   timeAnomalyScore?: number;
   sessionStateScore?: number;

4. In DetectionMonitor.tsx expanded breakdown (around line 346-401), replace the 
   derived scores with actual scores:
   - Rate Analysis bar: use `event.rateAnalyzerScore || 0` with max 35
   - Sequence Check bar: use `event.seqValidatorScore || 0` with max 25
   - Time Anomaly bar: use `event.timeAnomalyScore || 0` with max 15
   - Session State bar: use `event.sessionStateScore || 0` with max 20
   
   Example for Rate Analysis:
       style={{ width: `${Math.min(((event.rateAnalyzerScore || 0) / 35) * 100, 100)}%` }}
       <span>{event.rateAnalyzerScore || 0}/35</span>
```

---

## P3-1: Add Toast Notifications for Real-Time Attacks

**Prompt**:
```
Add a toast notification system that shows a floating alert when a CRITICAL or HIGH 
severity attack is detected in real-time.

1. Create a new component: src/components/ToastNotification.tsx
   - Fixed position at top-right of screen (top-4 right-4, z-50)
   - Shows attacker MAC, score, and severity
   - Red gradient background for CRITICAL, orange for HIGH
   - Auto-dismiss after 8 seconds with a progress bar
   - Entrance animation (slide from right)
   - Close button

2. In AdminDashboard.tsx and DetectionMonitor.tsx:
   - Import the toast component
   - When `latestAlert` from useDetectionStatus changes AND severity is 
     CRITICAL or HIGH, show the toast
   - Use a state array for multiple simultaneous toasts

Keep it simple — no external library. Use CSS animations and setTimeout.
```

---

## P3-2: Implement Network-Specific Filtering in DetectionMonitor

**Prompt**:
```
The network selector dropdown in DetectionMonitor.tsx (line 196-205) exists but doesn't
actually filter events. Fix this:

1. When selectedNetwork is NOT "all", filter the events list by matching 
   event.targetBssid against the selected network's BSSID:
   
   const filteredEvents = selectedNetwork === 'all' 
       ? events 
       : events.filter(e => {
           const network = networks.find(n => n.wifiId === selectedNetwork);
           return network && e.targetBssid?.toUpperCase() === network.bssid.toUpperCase();
       });

2. Use filteredEvents instead of events for:
   - The stats calculations (lines 105-112)
   - The event list rendering (line 298)

3. Also update the stats to show filtered counts when a specific network is selected,
   with a subtle label "(filtered)" next to the stat card titles.
```

---

## P3-3: Persist Prevention History to Database

**Prompt**:
```
Prevention history is currently in-memory only (Python dict + Java ConcurrentHashMap).
If either service restarts, all block history is lost.

1. Create a new JPA entity: PreventionAction.java
   @Entity @Table(name = "prevention_actions")
   Fields:
   - actionId (Long, auto-generated)
   - mac (String, CHAR(17))
   - action (String: MONITOR, TEMP_BLOCK, FULL_BLOCK, COUNTER_ATTACK, UNBLOCK)
   - level (Integer)
   - confidence (Double)
   - blockedAt (LocalDateTime)
   - expiresAt (LocalDateTime, nullable — null for permanent)
   - releasedAt (LocalDateTime, nullable)
   - status (String: ACTIVE, EXPIRED, RELEASED)
   - createdAt, updatedAt

2. Create PreventionActionRepository with:
   - findByMacAndStatus(mac, status)
   - findByStatusOrderByBlockedAtDesc(status)
   - findByExpiresAtBeforeAndStatus(now, "ACTIVE") — for cleanup job

3. Update PreventionController:
   - On block: save a PreventionAction with status ACTIVE
   - On unblock: update status to RELEASED, set releasedAt
   - On GET /blocklist: query DB for ACTIVE actions instead of in-memory map
   
4. Add a @Scheduled method (every 30s) to auto-release expired temp blocks:
   - Query for ACTIVE blocks where expiresAt < now
   - Update status to EXPIRED

This ensures block history survives restarts and provides an audit trail.
```

---

## P3-4: Add ML Model Accuracy Display

**Prompt**:
```
Add a small ML insights card to DetectionMonitor or AdminDashboard showing 
model performance stats.

1. Add a new Flask endpoint in ml-api/app.py:
   @app.route('/model-stats', methods=['GET'])
   Returns: {
       "models": {
           "decision_tree": {"loaded": true, "type": "DecisionTreeClassifier"},
           "random_forest": {"loaded": true, "type": "RandomForestClassifier"},
           "logistic_regression": {"loaded": true, "type": "LogisticRegression"},
           "xgboost": {"loaded": true, "type": "XGBClassifier"}
       },
       "total_predictions": <counter>,
       "attack_predictions": <counter>,
       "normal_predictions": <counter>,
       "average_confidence": <float>,
       "model_agreement_rate": <float>  // % of predictions where all 4 agree
   }
   Track these counters by incrementing them in the /predict endpoint.

2. In the Java backend, add a proxy endpoint or let the frontend call ML API directly.

3. In the frontend, create a small card component showing:
   - Models loaded: 4/4
   - Total predictions processed
   - Average confidence
   - Model agreement rate
   Place it in the DetectionMonitor stats section or as a sidebar card.
```
