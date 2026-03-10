# WiFi Security Platform — Prevention Module Status

_Last updated: 2026-02-21_

---

## What Is the Prevention Module?

The Prevention module is **Layer 4** — the final automated response layer after detection confirms an attack. It takes the detection output (threat score, ML confidence) and escalates through 4 response levels.

```
Level 1 (40–60%)  → Monitor only (fingerprint, log forensics)
Level 2 (60–85%)  → Temp block (5 min) + PMF preparation
Level 3 (85–95%)  → Permanent blacklist + PMF mandatory
Level 4 (>95%)    → Active defense (channel hop + counter-attack)
```

---

## DONE ✅ — What's Built and Working

### Backend (Java Spring Boot)

| Component | File | Status |
|-----------|------|--------|
| `PreventionController` | `controller/PreventionController.java` | ✅ Working |
| `GET /api/prevention/blocklist` | merges in-memory + DB ACTIVE records | ✅ Working |
| `DELETE /api/prevention/blocklist/{mac}` | manual unblock (in-memory + DB) | ✅ Working |
| `POST /api/prevention/notify` | receives Python engine events, broadcasts SSE | ✅ Working |
| `PreventionAction` entity | DB persistence for block/unblock/expire records | ✅ Working |
| `PreventionActionRepository` | JPA queries for ACTIVE, EXPIRED, RELEASED | ✅ Working |
| Scheduled expiry | `@Scheduled(fixedDelay=30s)` auto-expires timed blocks | ✅ Working |
| `addBlockedMac()` static helper | called by Layer1Service for immediate blocks | ✅ Working |

### Frontend (React)

| Component | File | Status |
|-----------|------|--------|
| `PreventionDashboard.tsx` | full page UI | ✅ Working |
| Defense Pipeline visualization | 4 levels shown as cards | ✅ Working |
| Blocked MACs table | live-polling every 5s, shows level + expiry | ✅ Working |
| Manual Unblock button | calls `DELETE /api/prevention/blocklist/{mac}` | ✅ Working |
| Real-Time Prevention Feed | SSE stream of BLOCK_ALERT / CRITICAL_ALERT / COUNTER_ATTACK / UNBLOCK events | ✅ Working |
| System Configuration panel | hard-coded read-only config display | ✅ Working |

### Python Prevention Engine

| Component | File | Status |
|-----------|------|--------|
| `main_engine.py` | SSE listener + action dispatcher | ✅ Built |
| `mac_blocker.py` | in-memory + iptables block logic | ✅ Built |
| `pmf_manager.py` | 802.11w PMF management | ✅ Built |
| `behavioral_tracker.py` | per-MAC attack history tracking | ✅ Built |
| `channel_hopper.py` | AP channel change logic (Level 4) | ✅ Built |
| `honeypot_manager.py` | honeypot AP deployment (Level 4) | ✅ Built |
| `counter_attack.py` | counter-deauth system (Level 4, conservative) | ✅ Built |
| `notification_service.py` | dashboard alerts (email/SMS disabled) | ✅ Built |
| `forensics_collector.py` | pcap capture + forensic reports | ✅ Built |
| `config.yaml` | all thresholds and Level 4 legal mode config | ✅ Built |

---

## INCOMPLETE ❌ — What's NOT Done Yet

### 1. Python Prevention Engine Is NOT Running
**Impact: HIGH** — The `prevention-engine/main_engine.py` is written but is never started. There is no `make run-prevention` target in the `Makefile`.

- The engine is supposed to listen on the SSE stream (`/api/detection/stream`)
- Detect attacks from the stream in real-time
- Call `/api/prevention/notify` to trigger blocks
- **Without it running, NO automatic blocking ever happens**

**What exists:** `prevention-engine/main_engine.py` starts, connects SSE, dispatches actions
**What's missing:**
- `Makefile` target: `run-prevention`
- The engine is never called during actual attacks
- `launchCounterAttack` in `preventionService.ts` (frontend) has no backend endpoint

---

### 2. No `POST /api/prevention/block` Endpoint (Manual Block from UI)
**Impact: MEDIUM** — Users cannot manually block a MAC from the dashboard. The Unblock button exists but there's no "Block MAC" form or button on the frontend, and no corresponding backend endpoint.

**What's missing:**
- `POST /api/prevention/blocklist` endpoint in `PreventionController.java`
- A "Block MAC" input/button on `PreventionDashboard.tsx`

---

### 3. No `GET /api/prevention/history` Endpoint (Block History)
**Impact: LOW** — The DB stores RELEASED + EXPIRED records (`PreventionAction` with status) but the frontend never reads them. The Prevention Dashboard only shows **currently active** blocks, not past ones.

**What's missing:**
- `GET /api/prevention/history` endpoint returning all `PreventionAction` records (ACTIVE + EXPIRED + RELEASED)
- A "History" tab or section on `PreventionDashboard.tsx`

---

### 4. Prevention Feed Is Empty (No Auto-Triggers in Current Flow)
**Impact: HIGH** — The Prevention Feed on the dashboard shows "Listening for engine telemetry…" indefinitely during attacks.

**Root cause:** The SSE feed filter only shows events with types:
`UNBLOCK, MONITOR_ALERT, BLOCK_ALERT, CRITICAL_ALERT, COUNTER_ATTACK`

But the detection system currently only broadcasts `ATTACK_DETECTED` and `STATUS_UPDATE` events. The prevention-type events are only generated when the Python engine calls `POST /api/prevention/notify` — which never happens because the engine isn't running.

**What's missing:** Either:
- Start the Python engine (fix #1 above), OR
- Have the Java backend send `MONITOR_ALERT` / `BLOCK_ALERT` SSE events automatically when `triggerAttack()` fires

---

### 5. `launchCounterAttack` Frontend API Has No Backend Endpoint
**Impact: LOW** — `preventionService.ts` references a `launchCounterAttack` method. The backend has no matching endpoint. If it's ever called, it will 404.

---

## Priority Fix Order

| Priority | Task | Effort |
|----------|------|--------|
| 🔴 HIGH | Wire Java backend to emit `MONITOR_ALERT` / `BLOCK_ALERT` SSE events when `triggerAttack()` fires | ~1 hour |
| 🔴 HIGH | Add `make run-prevention` Makefile target + ensure engine connects | ~30 min |
| 🟡 MEDIUM | Add `POST /api/prevention/blocklist` (manual block endpoint + frontend form) | ~45 min |
| 🟢 LOW | Add `GET /api/prevention/history` + history tab on dashboard | ~45 min |
| 🟢 LOW | Remove or stub out `launchCounterAttack` from frontend | ~10 min |

---

## Quick Check — What You See Right Now

| What you see | Why |
|---|---|
| Prevention Feed always empty | Python engine never running → no BLOCK_ALERT events |
| No automatic blocks ever | Python engine not started → no `POST /api/prevention/notify` calls |
| Blocked MACs table works | Only manual Unblock works because those are user-triggered |
| "Engine Online" badge shows | It's hard-coded, not actually checking if Python engine is up |
