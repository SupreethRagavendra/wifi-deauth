# Prevention System Troubleshooting Guide

## System Architecture

```
Sniffer (wlan2mon) → ML Detection (:5000) → Backend (:8080) → Prevention Engine (:5002) → Dashboard (:3000)
```

## Quick Diagnostic

```bash
bash scripts/diagnose_prevention.sh
```

## Common Issues

### 1. Prevention Engine Not Running

**Symptom**: `curl localhost:5002/health` returns nothing  
**Fix**: `sudo python3 prevention-engine/level1.py`  
**Or**: `bash scripts/start_prevention_properly.sh`

### 2. No Detection Events in Backend

**Symptom**: `curl localhost:8080/api/detection/events/recent` returns `[]`  
**Causes**:
- Sniffer not running or on wrong channel
- ML detection service down
- Sniffer/ML not posting to backend

**Fix**: Restart the full pipeline:
```bash
make run-sniffer CHANNEL=1   # Terminal 1
make run-ml                  # Terminal 2
make run-backend             # Terminal 3
```

### 3. Detection Scores Too Low

**Symptom**: Events exist but totalScore < 40  
**Why**: L1 only triggers at ≥40% confidence  
**Fix**: Run a sustained attack — short bursts may produce low scores:
```bash
sudo aireplay-ng --deauth 100 -a 9E:A8:2C:C2:1F:D9 -c 94:65:2D:97:25:87 wlan0mon
```

### 4. Prevention Dashboard Empty

**Symptom**: Dashboard at `/prevention` shows no data  
**Causes**:
- Prevention engine not running
- CORS blocking requests from `:3000` to `:5002`
- Engine has no stored prevention events

**Fix**:
```bash
# 1. Check engine
curl http://localhost:5002/stats

# 2. Check events
curl http://localhost:5002/prevention/events?limit=5

# 3. Manual trigger to force an event
curl -X POST http://localhost:5002/prevention/apply \
  -H "Content-Type: application/json" \
  -d '{"confidence": 75, "attacker_mac": "AA:BB:CC:DD:EE:FF", "victim_mac": "94:65:2D:97:25:87"}'
```

### 5. Sniffer/Attacker on Wrong Channel

**Symptom**: Deauth frames sent but sniffer doesn't see them  
**Fix**: Ensure both interfaces are on the same channel as the AP:
```bash
sudo iwconfig wlan2mon channel 1
sudo iwconfig wlan0mon channel 1
```

### 6. Log Files Permission Denied

**Symptom**: `PermissionError` on `logs/components.log`  
**Fix**:
```bash
sudo rm -rf prevention-engine/logs
mkdir -p prevention-engine/logs
```

## Confidence Thresholds

| Level | Threshold | Components |
|-------|-----------|------------|
| L1    | ≥ 40%     | OKC, Fast Probe, Channel Cache, Pre-Auth |
| L2    | ≥ 60%     | TCP, MPTCP, Buffers, Download Mgr |
| L3    | ≥ 85%     | Perceptual Masking, Notification Suppression, Handoff, Degradation |
| L4    | ≥ 95%     | Edge Cache, Dual-Radio, Mesh, SDN |

## Diagnostic Scripts

| Script | Purpose |
|--------|---------|
| `diagnose_prevention.sh` | Full pipeline check |
| `fix_detection_to_backend.py` | Test detection → backend |
| `fix_backend_to_prevention.py` | Test backend → engine |
| `start_prevention_properly.sh` | Robust engine startup |
| `verify_attack_detection.sh` | Attack detection E2E |
| `fix_prevention_system.sh` | Master fix (runs all) |

## Manual Test (No Real Attack)

```bash
# Simulate a 75% confidence detection event
python3 prevention-engine/tests/mock_attack.py 75

# Simulate a 98% confidence event (triggers all 4 levels)
python3 prevention-engine/tests/mock_attack.py 98
```
