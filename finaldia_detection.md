# WiFi Deauth Detection System — Final Detection Flow
> Source-verified: all numbers pulled directly from Java source code

---

## Overview

Every deauth frame captured by the sniffer flows through **3 analysis layers** → a **final scoring formula** → a **threat classification** → an **action decision**.

```
Deauth Packet
     │
     ▼
┌─────────────────────────────────────┐
│  LAYER 1 — Fast Heuristics (≤5ms)  │  Max score: 95 pts
│  4 analyzers run in parallel        │
└──────────────────┬──────────────────┘
                   │  score ≥ 5 AND frameType == DEAUTH?
                   ▼ YES
┌─────────────────────────────────────┐
│  LAYER 2 — ML Ensemble              │  Score: 0–100
│  Decision Tree / RF / LR / XGBoost │
└──────────────────┬──────────────────┘
                   │  (always runs too)
                   ▼
┌─────────────────────────────────────┐
│  LAYER 3 — Physical Checks          │  Max score: 70 pts
│  RSSI + Multi-Client + Broadcast    │
└──────────────────┬──────────────────┘
                   │
                   ▼
          FINAL SCORE FORMULA
          + Safety Floor + RSSI Boost
                   │
                   ▼
         THREAT LEVEL + ACTION
```

---

## LAYER 1 — Fast Heuristics

**File:** `Layer1Service.java` + 4 sub-analyzers  
**Execution:** All 4 analyzers run **in parallel** (CompletableFuture), timeout = **5ms**

### 4 Analyzers

---

#### 1. RateAnalyzer
**File:** `RateAnalyzer.java`  
Counts deauth frames from the same `(sourceMac, BSSID)` pair in the last **10 seconds**.

| Frames in 10s | Score |
|---|---|
| ≤ 5 | **0** — Normal |
| ≤ 10 | **40** — Slightly Suspicious |
| ≤ 25 | **70** — Suspicious |
| > 25 | **100** — Attack |

---

#### 2. SequenceValidator
**File:** `SequenceValidator.java`  
Checks for **duplicate or out-of-order sequence numbers** from the same MAC.
- Legitimate devices increment sequence numbers sequentially
- Attackers often replay or repeat sequence numbers

Score range: **0–100**

---

#### 3. TimeAnomalyDetector
**File:** `TimeAnomalyDetector.java`  
Detects **burst timing anomalies** — frames arriving in machine-speed batches vs. human/normal device timing.

Score range: **0–100**

---

#### 4. SessionStateChecker
**File:** `SessionStateChecker.java`  
Validates that deauth frames match **expected client state transitions**.  
e.g. A deauth from a client that was never associated is suspicious.

Score range: **0–100**

---

### Layer 1 Combined Score Formula

```
L1_score = ROUND(
    Rate  × 0.35 +
    Seq   × 0.25 +
    Time  × 0.15 +
    Session × 0.20
)

Maximum possible = (100×0.35) + (100×0.25) + (100×0.15) + (100×0.20)
                 = 35 + 25 + 15 + 20 = 95 pts
```

| Weight | Analyzer | Why |
|---|---|---|
| **35%** | RateAnalyzer | Most reliable single indicator |
| **25%** | SequenceValidator | Strong attacker signature |
| **20%** | SessionStateChecker | Context validation |
| **15%** | TimeAnomalyDetector | Burst timing |

### Layer 1 Threat Level (from L1 score alone)

| L1 Score | Severity |
|---|---|
| ≥ 50 | **CRITICAL** |
| ≥ 30 | **HIGH** |
| ≥ 15 | **MEDIUM** |
| < 15 | **LOW** |

> The event is **saved to DB** immediately after Layer 1 with the L1 score and severity. It gets **updated in-place** after Layer 2 & 3 finish.

---

## LAYER 2 — ML Ensemble

**File:** `Layer2Service.java`, `FeatureExtractor.java`, `ml-api/app.py`  
**Gate:** Only runs if `L1_score ≥ 5` AND `frameType == "DEAUTH"`

### Models

| Model | Type | Output |
|---|---|---|
| Decision Tree | Classical | Attack / Normal |
| Random Forest | Ensemble | Attack / Normal |
| Logistic Regression | Linear | Attack / Normal |
| XGBoost | Gradient Boost | Attack / Normal |

**Voting:** Majority vote across 4 models  
**Confidence:** % of models that agree (e.g. 3/4 = 75%)

### Features Extracted (FeatureExtractor.java)
- Deauth rate (frames/sec)
- Sequence number anomaly
- RSSI value
- Time delta between frames
- Broadcast flag
- Multi-client flag

### Output
- `mlScore` — 0 to 100 (Attack confidence scaled)
- `mlConfidence` — 0.0 to 1.0 (e.g. 0.75 = 75% of models agree)
- `mlPrediction` — "ATTACK" or "NORMAL"
- `modelAgreement` — e.g. "3/4"

---

## LAYER 3 — Physical Checks

**File:** `Layer3Service.java`  
**Gate:** **Always runs** (regardless of ML result) — provides physical-layer corroboration

### 3 Checks

#### 1. RSSI Sanity Check (max 30 pts)

| Signal Strength | Score | Reasoning |
|---|---|---|
| Missing / null | **20 pts** | Suspicious — real devices always have signal |
| −50 to −30 dBm | **30 pts** | Suspiciously strong — possible spoofed device close by |
| −70 to −50 dBm | **15 pts** | Unusual range |
| < −85 dBm | **0 pts** | Weak = likely normal distant device |

#### 2. Multi-Client Pattern (max 25 pts)
Tracks unique **target MACs** attacked by the same source MAC in a **10-second rolling window**.

| Unique Targets in 10s | Score |
|---|---|
| 1 | **0 pts** |
| 2 | **15 pts** |
| ≥ 3 | **25 pts** |

#### 3. Broadcast Check (max 15 pts)

| Target MAC | Score |
|---|---|
| `FF:FF:FF:FF:FF:FF` | **15 pts** — attacking all devices |
| Unicast | **0 pts** |

### Layer 3 Total
```
L3_score = min(70,  rssiScore + multiClientScore + broadcastScore)
           Max = 30 + 25 + 15 = 70 pts (capped at 70)
```

---

## FINAL SCORE FORMULA

**File:** `DetectionService.java` → `analyzePayload()`

### Step 1 — Normalize each layer to 0–100

```
normL1 = min(100,  (L1_score / 95.0) × 100 )   // L1 max is 95
normL2 = mlScore                                  // already 0–100
normL3 = min(100,  (L3_score / 70.0) × 100 )   // L3 max is 70
```

### Step 2 — Weighted Final Score

```
finalScore = ROUND(
    normL1 × 0.30 +     // Layer 1 Heuristics — 30%
    normL2 × 0.50 +     // Layer 2 ML         — 50%
    normL3 × 0.20       // Layer 3 Physical   — 20%
)
```

### Step 3 — RSSI Boost (if sniffer detected spoofing)

If the Python sniffer confirmed MAC spoofing via RSSI deviation analysis,  
it attaches a `scoreBoost` field (typically +30 to +50 pts) to the packet.

```
finalScore = min(100, finalScore + scoreBoost)
```

### Step 4 — Safety Floor

Ensures the final score never drops *below* the raw Layer 1 score:

```
finalScore = max(finalScore, L1_score)
```

This prevents ML from inadvertently downgrading an obvious flood.

---

## THREAT LEVEL (from finalScore)

| Final Score | Severity | Alert Type |
|---|---|---|
| ≥ 50 | **CRITICAL** | `CRITICAL_ALERT` — Prevention Engine blocks MAC 30 min |
| ≥ 30 | **HIGH** | `BLOCK_ALERT` — PMF defense triggered |
| ≥ 15 | **MEDIUM** | `MONITOR_ALERT` — Logged, no block |
| < 15 | **LOW** | Shown in feed only |

---

## ACTION DECISION

```
mlConfirmsAttack    = (mlConfidence > 0.60)
layer1ConfirmsAttack = (L1_score >= 20)

if (mlConfirmsAttack OR layer1ConfirmsAttack):
    → triggerAttack()   sets underAttack = true
                        broadcasts DEAUTH_FLOOD alert

elif (finalScore >= 10):
    → broadcastMinorEvent()   no state change, logged in feed

else (score < 10):
    → silently ignored
```

### Attack State Cooldown

```
ATTACK_COOLDOWN = 8 seconds

underAttack stays true until:
    (now - lastAttackTime) > 8000 ms

Status flip: UNSAFE → SAFE after 8s of silence
Status check: every 2 seconds (scheduled task)
```

---

## Per-Score Alert Levels in triggerAttack()

Once `triggerAttack()` fires, a secondary tiered alert is also sent based on the final score:

| Final Score | Defense Level | Action |
|---|---|---|
| ≥ 85 | **LEVEL 3 — CRITICAL** | PMF + Channel Hop deployed |
| ≥ 60 | **LEVEL 2 — HIGH** | PMF (`802.11w`) enabled |
| ≥ 40 | **LEVEL 1 — MEDIUM** | Monitor only |
| < 40 | — | Silent |

---

## Database: Event Lifecycle

```
[Layer 1 completes]
    → DetectionEvent saved to DB
      (layer1Score, rateScore, seqScore, timeScore, sessionScore, severity=L1 threat)

[Layer 2 + 3 complete]
    → updateWithMlScores() updates the SAME event row by eventId
      (layer2Score, mlConfidence, mlPrediction, layer3Score, totalScore=finalScore)
      (severity re-evaluated based on finalScore)
```

> eventId is passed from Layer 1 save → Layer 2 so no race condition.

---

## Quick Reference — All Thresholds

| Parameter | Value | Source |
|---|---|---|
| Layer 1 timeout | **5 ms** | `Layer1Service` `@Value` |
| RateAnalyzer window | **10 seconds** | `RateAnalyzer.analyzeRate()` |
| Rate: Normal threshold | **≤ 5 frames** | `RateAnalyzer` |
| Rate: Suspicious threshold | **≤ 10 frames** | `RateAnalyzer` |
| Rate: Attack threshold | **> 25 frames** | `RateAnalyzer` |
| ML gate (min L1 score) | **≥ 5** | `DetectionService.analyzePayload()` |
| ML trigger (attack) | **confidence > 60%** | `DetectionService` |
| L1 trigger (attack) | **L1 score ≥ 20** | `DetectionService` |
| Multi-client window | **10 seconds** | `Layer3Service` |
| Attack cooldown | **8 seconds** | `DetectionService` |
| Status broadcast interval | **2 seconds** | `@Scheduled(fixedRate=2000)` |
| Final score weights | **L1:30%, L2:50%, L3:20%** | `DetectionService` |
| CRITICAL threshold | **final ≥ 50** | `DetectionService` |
| HIGH threshold | **final ≥ 30** | `DetectionService` |
| MEDIUM threshold | **final ≥ 15** | `DetectionService` |
| Prevention block duration | **30 minutes** | `Layer1Service.saveAnomaly()` |
