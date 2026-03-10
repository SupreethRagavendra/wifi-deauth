# WiFi Deauthentication Detection & Prevention System — Full Project Analysis

> **Purpose**: Comprehensive reference document for understanding, debugging, and extending this system.
> **Test MACs**: WiFi BSSID `9E:A8:2C:C2:1F:D9` · User Device `4C:6F:9C:F4:FA:63`

---

## 1. System Architecture

```
┌──────────────────┐     HTTP POST      ┌──────────────────────┐     REST      ┌──────────────────┐
│  Packet Capture  │ ──── /deauth/batch ──> │   Spring Boot Backend  │ ──── /predict ──> │   ML API (Flask)   │
│  (Python/Scapy)  │                     │    (Java 17)           │ <──────────── │  + PreventionEngine│
└──────────────────┘                     │                        │              └──────────────────┘
                                         │  ┌─ Layer 1 (Heuristics)│
                                         │  ├─ Layer 2 (ML)        │
                                         │  └─ Layer 3 (Physical)  │
                                         │                        │
                                         │  SSE /detection/stream  │
                                         └─────────┬──────────────┘
                                                    │ Server-Sent Events
                                                    ▼
                                         ┌──────────────────────┐
                                         │   React Frontend      │
                                         │  (AdminDashboard,     │
                                         │   DetectionMonitor,   │
                                         │   PreventionDashboard)│
                                         └──────────────────────┘
```

### Data Flow Summary
1. **Capture** → `PacketSniffer` (Scapy monitor mode) captures 802.11 deauth frames on configured channel
2. **Buffer** → `DataSender` queues packets, sends batches via HTTP POST to backend `/api/packets/deauth/batch`
3. **Ingest** → `PacketController.receiveBatch()` → `DetectionService.processBatch()`
4. **Persist** → Each packet saved to MySQL `captured_packets` table
5. **Analyze** → Per unique source MAC: `analyzePayload()` runs L1 → L2 → L3 pipeline
6. **Score** → Weighted final score: L1 (30%) + L2 (50%) + L3 (20%)
7. **Alert** → SSE broadcast via `AlertService` to all connected frontend clients
8. **Prevent** → Critical threats auto-blocked via `PreventionController.addBlockedMac()`

---

## 2. Component Deep Dive

### 2.1 Packet Capture (`packet-capture/`)

| File | Purpose |
|------|---------|
| `main.py` | Entry point — root check, monitor mode, channel setup, graceful shutdown |
| `packet_sniffer.py` | Scapy sniff loop filtering `Dot11Deauth`, extracts src/dst/bssid/seq/rssi/reason |
| `data_sender.py` | Thread-safe queue → batch HTTP POST with retry logic + direct `/detection/alert` |
| `frame_parser.py` | `build_packet_json()` — formats fields to match backend DTO (ISO 8601 timestamps) |
| `config.py` | `.env` loader: `INTERFACE`, `BACKEND_URL`, `CHANNEL`, `BUFFER_SIZE`, `RETRY_*` |

**Config defaults**: `wlan1mon`, `http://localhost:8080/api`, channel 1, buffer 10, max retries 3

### 2.2 Backend (`wifi-security-backend/`)

#### Controllers
| Controller | Key Endpoints |
|-----------|--------------|
| `PacketController` | `POST /api/packets/deauth` (single), `POST /api/packets/deauth/batch` |
| `DetectionController` | `GET /live-status`, `GET /status`, `GET /events/recent`, `GET /threat-level`, `GET /stream` (SSE), `DELETE /events` |
| `PreventionController` | `GET /blocklist`, `DELETE /blocklist/{mac}`, `POST /notify` |

#### DetectionService (Core Orchestrator)
- `processBatch()`: Persists packets → groups by source MAC → calls `analyzePayload()` per source
- `analyzePayload()`: Sequential L1 → conditional L2 → L3 pipeline
  - **L1 trigger for L2**: Runs ML if L1 score ≥ `suspiciousThreshold` (default 30)
  - **Final decision**: `mlConfidence > 0.75` OR `L1 score ≥ suspiciousThreshold` → `triggerAttack()`
  - Otherwise → `broadcastMinorEvent()`
- State: `AtomicLong totalPacketsProcessed`, `AtomicBoolean underAttack`, `CopyOnWriteArrayList attackDetails`
- Attack cooldown: 30 seconds (`ATTACK_COOLDOWN_MS`)

#### Layer 1 Service (Heuristics — `layer1/`)
4 parallel analyzers via `CompletableFuture` (5ms timeout):
- **RateAnalyzer**: Frame rate anomaly detection
- **SequenceValidator**: Sequence number gap analysis
- **TimeAnomalyDetector**: Temporal pattern detection
- **SessionStateChecker**: Session context validation

Weighted scoring: Rate (35%) + Sequence (25%) + Time (15%) + Session (20%) = max 95 pts

Thresholds (configurable via `application.properties`):
- `attack-threshold`: 50 → CRITICAL
- `suspicious-threshold`: 30 → HIGH
- `warning-threshold`: 15 → MEDIUM
- Below 15 → LOW

**Important**: `saveAnomaly()` only persists events with severity > LOW to prevent DB flooding. CRITICAL events auto-block the attacker for 30 minutes.

#### Layer 2 Service (ML — `layer2/`)
- REST call to ML API `POST /predict` with 500ms connect/read timeout
- Payload: `{src, dst, bssid, signal, channel, reason, seq, timestamp}`
- Response parsed as `Layer2Response`: `mlScore`, `prediction`, `confidence`, `modelAgreement`
- Fallback on timeout/error: score=0, prediction="UNKNOWN", confidence=0.0, agreement="0/4"

#### Layer 3 Service (Physical — `layer3/`)
3 checks:
- **RSSI Sanity**: Missing signal (20), suspiciously strong -50 to -30 (30), unusual -70 to -50 (15)
- **Multi-client Pattern**: Same source attacking ≥3 targets (25), 2 targets (15)
- **Broadcast Check**: Target is `FF:FF:FF:FF:FF:FF` (15)

Max physical score: capped at 70

#### AlertService (SSE Broadcasting)
- Maintains `CopyOnWriteArrayList<SseEmitter>` for connected clients
- Two event types: `"alert"` (threat data) and `"status"` (system state)
- Dead emitters auto-cleaned on send failure
- Max 500 total alerts, 100 active alerts in memory

#### DetectionEvent Entity
Key fields for frontend display:
- `layer1Score`, `layer2Score`, `layer3Score`, `totalScore`
- `mlConfidence` (Double), `mlPrediction` (String), `modelAgreement` (String)
- `severity` (enum: LOW, MEDIUM, HIGH, CRITICAL)
- `attackerMac`, `targetMac`, `targetBssid`
- JSON annotations: `@JsonProperty("layer2Score")`, `@JsonProperty("mlConfidence")`, etc.

### 2.3 ML API (`ml-api/`)

#### `app.py` (Flask)
- Loads 4 models at startup: Decision Tree, Random Forest, Logistic Regression, XGBoost (pickle/joblib)
- **`/predict`**: Extracts 13 features → predicts with all 4 models → ensemble voting
- **`/full-analysis`**: Integrates with `PreventionEngine` — mocks L1/L3, determines action based on confidence
- Feature engineering: `log_timestamp`, `burst_score`, `mac_entropy`, `seq_delta`, etc.
- `adjust_features()`: Pads/trims feature vector to match model expectations (13 features)

#### `prevention_engine.py` (4-Level Response)
| Level | Action | Threshold | Duration |
|-------|--------|-----------|----------|
| 1 | Monitor + watchlist | 40% confidence | Auto-escalate after 30s if continues |
| 2 | Temp Block (iptables) | 60% confidence | 5 min auto-release |
| 3 | Full Block (iptables) | 85% confidence | Permanent |
| 4 | Counter-Attack | 95% + aggressive mode | Fake handshakes + honeypot AP |

Key: The Python prevention engine uses `iptables` directly. The Java backend has a separate in-memory blocklist in `PreventionController` (ConcurrentHashMap). Both systems can block MACs but operate independently.

### 2.4 Frontend (`wifi-security-frontend/`)

#### Pages
| Page | Key Features |
|------|-------------|
| `AdminDashboard` | Network management (CRUD + scan), stats grid (packets/threats/connection), DetectionFeed component |
| `DetectionMonitor` | Real-time event feed with expandable heuristics breakdown, 5 stat cards (Active/Normal/Suspicious/Attacks/Critical) |
| `PreventionDashboard` | Blocked MACs table, real-time SSE prevention feed, 4-level pipeline visualization, system config (read-only) |

#### Hooks
- **`useDetectionStatus`**: SSE connection to `/api/detection/stream` + REST polling every 2s as backup
  - Listens for `"status"` and `"alert"` events
  - Returns: `isUnderAttack`, `totalPackets`, `totalThreats`, `connected`, `latestAlert`, `alerts`
- **`useLiveStatus`**: REST polling `/api/detection/live-status` every 3s
  - Returns: `systemStatus`, `activeThreats`, `threatsLastHour`, `underAttack`

#### API Service (`services/api.ts`)
- Axios instance with Bearer token auth, 30s timeout
- Services: `authService`, `wifiService`, `detectionService`, `preventionService`
- Token persistence: `localStorage` (`wifi_shield_token`, `wifi_shield_user`)

---

## 3. Known Issues & Root Causes

### 3.1 Detection Stats Bugs

| Issue | Root Cause | Fix Location |
|-------|-----------|-------------|
| "Attacks Detected (1hr)" capped/not increasing | `threatsLastHour` comes from `useLiveStatus` → `GET /detection/live-status` → `DetectionController.getLiveStatus()` which queries DB events from last 60 min. If `saveAnomaly()` filters LOW events, the count only reflects MEDIUM+ severity events | `Layer1Service.saveAnomaly()` line 348 + `DetectionController.getLiveStatus()` |
| System shows "Safe" during attacks | `useLiveStatus` polls every 3s. `DetectionController.getLiveStatus()` calls `layer1Service.isCurrentlyUnderAttack()` which checks for CRITICAL/HIGH events in last 15 seconds. If events are saved as MEDIUM, they won't trigger "underAttack" | `Layer1Service.isCurrentlyUnderAttack()` severity check |
| "Normal" count inflating during attacks | `DetectionMonitor` counts `events.filter(e => e.severity === 'LOW')` but real-time SSE alerts pushed via `useDetectionStatus` create synthetic events with `layer1Score: latestAlert.packetCount` (which is actually the score, not packet count) and `severity: latestAlert.severity`. If SSE alert severity mappings don't match, events may be miscategorized | `DetectionMonitor.tsx` lines 85-101 + `useDetectionStatus.ts` SSE alert handler |

### 3.2 ML Confidence Showing as 0

**Pipeline**: `DetectionService.analyzePayload()` → `Layer2Service.analyzeWithML()` → ML API `/predict` → response → `layer1Service.updateWithMlScores()` → DB update → frontend fetch

**Potential break points**:
1. ML API returns `confidence: 0.0` if all models predict "Normal" (check ML API logs)
2. `Layer2Response` field mapping: Java expects `mlScore`, `prediction`, `confidence`, `modelAgreement` — must match Flask JSON keys exactly
3. `updateWithMlScores()` finds the most recent event for the source MAC but if multiple events for same MAC exist rapidly, it may update the wrong one
4. Frontend `DetectionEvent` type has `mlConfidence?: number` — if backend serializes as different field name, it will be undefined

### 3.3 UI Consistency Issues

- **AdminDashboard**: Uses `bg-gray-50`, standard Tailwind, blue-600 primary
- **DetectionMonitor**: Same gray-50 scheme, consistent with AdminDashboard
- **PreventionDashboard**: Uses `bg-slate-50`, gradient headers, different typography weight (`font-black`), `glow-*` custom classes — visually distinct from other pages
- **Navigation**: AdminDashboard has nav links to Detection Monitor and Prevention; DetectionMonitor has Prevention link but no Admin link; PreventionDashboard has both

### 3.4 Dual Prevention Systems (Architecture Concern)

The Java backend `PreventionController` and the Python `PreventionEngine` both maintain blocklists **independently**:
- Java: `ConcurrentHashMap<String, Map<String, Object>> blocklist` (static, in-memory)
- Python: `prevention_engine.blocked_macs` dict + actual `iptables` rules

**Risk**: A MAC blocked by `Layer1Service.saveAnomaly()` (which calls `PreventionController.addBlockedMac()`) is NOT blocked in `iptables`. A MAC blocked by the ML API's `/full-analysis` (which calls `prevention_engine.act()`) IS blocked in `iptables` but the Java blocklist may not know about it unless the ML API POSTs to `/prevention/notify`.

---

## 4. Configuration Reference

### Backend (`application.properties`)
```properties
detection.layer1.timeout-ms=5
detection.layer1.attack-threshold=50
detection.layer1.suspicious-threshold=30
detection.layer1.warning-threshold=15
ml.api.url=http://localhost:5000
```

### Packet Capture (`.env`)
```env
INTERFACE=wlan1mon
BACKEND_URL=http://localhost:8080/api
CHANNEL=1
BUFFER_SIZE=10
MAX_RETRIES=3
RETRY_DELAY=2
```

### ML API
- Default port: 5000
- Models path: `ml-api/models/` (pickle files)
- Prevention thresholds: monitor=40, temp_block=60, full_block=85, counter_attack=95

---

## 5. API Endpoint Reference

### Packet Ingestion
| Method | Path | Body | Response |
|--------|------|------|----------|
| POST | `/api/packets/deauth` | `DeauthPacketDTO` | `{status, message}` |
| POST | `/api/packets/deauth/batch` | `{packets: DeauthPacketDTO[]}` | `{status, count}` |

### Detection
| Method | Path | Response |
|--------|------|----------|
| GET | `/api/detection/live-status` | `{systemStatus, activeThreats, threatsLastHour, underAttack}` |
| GET | `/api/detection/status` | `{status, isUnderAttack, totalPackets, attackDetails}` |
| GET | `/api/detection/events/recent` | `DetectionEvent[]` (top 100 by date DESC) |
| GET | `/api/detection/threat-level` | `{threatLevel, activeThreats, underAttack}` |
| GET | `/api/detection/stream` | SSE stream — events: `"status"`, `"alert"` |
| DELETE | `/api/detection/events` | Clears all detection events |

### Prevention
| Method | Path | Body | Response |
|--------|------|------|----------|
| GET | `/api/prevention/blocklist` | — | `BlockedMac[]` (active only) |
| DELETE | `/api/prevention/blocklist/{mac}` | — | `{success, message}` |
| POST | `/api/prevention/notify` | `{mac, action, level, confidence, duration}` | `{success}` |

### ML API
| Method | Path | Body | Response |
|--------|------|------|----------|
| GET | `/health` | — | `{status, models_loaded, model_count}` |
| POST | `/predict` | `{src, dst, bssid, signal, channel, reason, seq, timestamp}` | `{prediction, confidence, ml_score, model_agreement, models}` |
| POST | `/full-analysis` | Same as predict | Full analysis + prevention result |

---

## 6. Database Schema (Key Tables)

### `detection_events`
```sql
event_id          BIGINT AUTO_INCREMENT PRIMARY KEY
detected_at       DATETIME(6)
attack_type       ENUM('DEAUTH_FLOOD','TARGETED_DEAUTH','BROADCAST_DEAUTH',...)
severity          ENUM('LOW','MEDIUM','HIGH','CRITICAL')
layer1_score      TINYINT UNSIGNED
layer2_score      TINYINT UNSIGNED
layer3_score      TINYINT UNSIGNED
total_score       TINYINT UNSIGNED
ml_confidence     DOUBLE
ml_prediction     VARCHAR(50)
model_agreement   VARCHAR(10)
layer3_notes      TEXT
attacker_mac      CHAR(17)
victim_mac        CHAR(17)
target_bssid      CHAR(17)
frame_count       INT UNSIGNED
attack_duration_ms INT UNSIGNED
session_id        FK → attack_sessions
institute_id      VARCHAR(36)
```

Indexes: `detected_at DESC`, `attacker_mac + detected_at`, `severity + detected_at`, `institute_id + severity + detected_at`

---

## 7. Testing Scenarios

### Scenario 1: Normal Deauth (Legitimate Disconnect)
- Single deauth frame, valid sequence, normal RSSI (-70 to -85)
- Expected: L1 score < 15, severity LOW, NOT persisted to DB, no alert

### Scenario 2: Moderate Attack (Rate Anomaly)
- 10+ deauth frames/sec from same source, sequential numbers
- Expected: L1 score 30-50 → triggers ML (L2) → score 40-70 → MEDIUM/HIGH severity
- Dashboard: "Suspicious" count increases, system status may show "UNSAFE"

### Scenario 3: Full Attack (Flood)
- 50+ deauth frames/sec, broadcast target, strong RSSI
- Expected: L1 ≥ 50 → ML ≥ 75% confidence → L3 broadcast+multi-client → score 70+ → CRITICAL
- Dashboard: "Attacks" and "Critical" counts increase, auto-block triggered (30 min)
- Prevention: MAC added to Java blocklist + alert broadcast

### Scenario 4: Multi-target Attack
- Same source deauthing 3+ different targets
- Expected: L3 multi-client score 25, total score boosted → CRITICAL likely
- Prevention: Immediate block

### Scenario 5: Prevention Level Escalation (via ML API `/full-analysis`)
- Confidence 40% → Level 1 Monitor (watchlist, 30s auto-escalate timer)
- Confidence 60% → Level 2 Temp Block (5 min iptables, auto-release)
- Confidence 85% → Level 3 Full Block (permanent iptables)
- Confidence 95% + aggressive mode → Level 4 Counter-Attack (fake handshakes + honeypot)

---

## 8. Priority Fix List

### P0 — Critical (Detection Accuracy)
1. **Fix `isCurrentlyUnderAttack()`**: Include MEDIUM severity events in attack check, not just CRITICAL/HIGH
2. **Fix `threatsLastHour` query**: Ensure the DB query in `getLiveStatus()` counts all non-LOW events, not just CRITICAL/HIGH
3. **Fix SSE alert → DetectionMonitor mapping**: `latestAlert.packetCount` is being set to `response.getCombinedScore()` (not actual packet count) in `triggerAttack()` line 291

### P1 — Important (Data Integrity)
4. **Reconcile dual prevention systems**: Either make Java backend the single source of truth for blocking (removing iptables from Python) OR have the ML API always POST to `/prevention/notify` after any block action
5. **Fix `updateWithMlScores()` race condition**: When multiple events for same MAC arrive rapidly, finding "most recent" via `findTop100ByOrderByDetectedAtDesc()` may update wrong event. Use event ID instead.
6. **TINYINT UNSIGNED overflow**: `layer1_score`, `layer2_score`, `total_score` columns are `TINYINT UNSIGNED` (max 255). Scores can theoretically exceed this. Change to `SMALLINT UNSIGNED` or add validation.

### P2 — UI/UX
7. **Unify UI design language**: PreventionDashboard uses slate/gradient/glow styling vs gray-50/blue-600 on other pages. Standardize.
8. **Add "Admin Dashboard" link to DetectionMonitor** nav bar for consistent navigation
9. **Fix heuristics breakdown in DetectionMonitor**: Currently derives all 4 sub-scores by multiplying `layer1Score` by fixed weights — this shows the same proportional value for all events. Should use actual per-analyzer scores from the backend (requires storing `AnalyzerScore` in `DetectionEvent`)

### P3 — Enhancements
10. **Add toast/notification for real-time attacks** instead of relying on stat counters alone
11. **Implement network-specific filtering** in DetectionMonitor (the network selector exists but events aren't filtered by BSSID)
12. **Add ML model accuracy display** on Detection Monitor or a dedicated ML insights page
13. **Persist prevention history to DB** — currently in-memory only on both Java and Python sides

---

## 9. How to Launch the Full System

```bash
# 1. Start MySQL (ensure database exists)
sudo systemctl start mysql

# 2. Start ML API
make run-ml or
cd ml-api && python app.py   # Port 5000

# 3. Start Backend
make run-backend or 
cd wifi-security-backend && mvn spring-boot:run   # Port 8080

# 4. Start Frontend
OR make run-frontend
cd wifi-security-frontend && npm run dev   # Port 3000

# 5. Start Packet Capture (requires root + monitor mode interface)
cd packet-capture && sudo python main.py
```

### Verify System Health
- ML API: `curl http://localhost:5000/health`
- Backend: `curl http://localhost:8080/api/detection/live-status`
- Frontend: Open `http://localhost:3000`
- SSE: `curl -N http://localhost:8080/api/detection/stream`
