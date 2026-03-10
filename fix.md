# WiFi Deauth ML Integration - Full Prompt Reference

I have a WiFi Deauthentication Detection system with:

## EXISTING SYSTEM:
- Python sniffer (captures deauth packets)
- Java Spring Boot backend (Layer 1 heuristic detection)
- React frontend (dashboard)
- MySQL database (stores detection events)
- Layer 1 has 4 analyzers: RateAnalyzer(35pts), 
  SequenceValidator(25pts), TimeAnomalyDetector(15pts), 
  SessionStateChecker(20pts). Max score 95pts.

## EXISTING ML MODELS (trained in Colab):
- 4 models saved as .pkl files at /saved_models/
  - random_forest_model.pkl (96.3% accuracy)
  - xgboost_model.pkl (96.4% accuracy)  
  - logistic_regression_model.pkl (96.5% accuracy)
  - decision_tree_model.pkl (96.2% accuracy)
- standard_scaler.pkl (StandardScaler)
- feature_names.json (13 features)
- Features: frame_rate, seq_variance, mean_interval, 
  rssi, rssi_delta, hour, day_of_week, victim_count, 
  reason_code, time_since_legit, assoc_duration, 
  throughput, channel

## DETECTION FLOW:
```
Layer1 score < 10 → ALLOW (skip ML)
Layer1 score >= 10 AND is deauth frame → SEND TO LAYER 2 ML
Layer2 ML confidence > 75% → SEND TO LAYER 3 PHYSICAL
Final score = L1(30%) + L2(50%) + L3(20%)
```

## ATTACKS LAYER 1 CATCHES:
- Flood deauth (100+ frames/sec)
- Burst deauth (20-50 frames in 2 sec)
- Broadcast deauth (to FF:FF:FF:FF:FF:FF)
- Sequence spoofing (random seq numbers)

## ATTACKS ONLY LAYER 2 ML CAN CATCH:
- Slow-rate deauth (1 frame per 3-5 sec)
- Targeted smart deauth (mimics normal timing)
- Reason code manipulation (uses code 3 instead of 7)
- MAC rotation attacks (changes MAC every few frames)

---

## BUILD THESE COMPONENTS:

### COMPONENT 1: Python ML Microservice
File: `ml-service/ml_service.py`

Create a FastAPI microservice that:

1. On startup loads all 4 models, scaler, feature_names 
   from /saved_models/ folder using joblib

2. POST /predict endpoint:
   - Accepts JSON with raw packet features
   - Extracts/calculates 13 features from raw data:
     * frame_rate: calculate from packet timestamps
     * seq_variance: variance of recent sequence numbers
     * mean_interval: mean time between recent packets
     * rssi: signal strength from packet
     * rssi_delta: change in rssi from last packet
     * hour: current hour (0-23)
     * day_of_week: current day (0-6)
     * victim_count: unique destination MACs seen recently
     * reason_code: deauth reason code from packet
     * time_since_legit: seconds since last legitimate 
       (non-deauth) frame from this MAC
     * assoc_duration: how long the client was associated
       before this deauth
     * throughput: recent data throughput for this client
     * channel: WiFi channel number
   - Scale features using loaded StandardScaler
   - Run ALL 4 models on scaled features
   - Use MAJORITY VOTING: 3+ models agree → that prediction
   - Calculate confidence = average probability of all models
   - Return JSON:
     ```json
     {
       "prediction": "Attack" or "Normal",
       "confidence": 0.96,
       "ml_score": 96,
       "model_votes": {
         "random_forest": {"prediction": 1, "confidence": 0.97},
         "xgboost": {"prediction": 1, "confidence": 0.95},
         "logistic_regression": {"prediction": 1, "confidence": 0.94},
         "decision_tree": {"prediction": 1, "confidence": 0.93}
       },
       "ensemble_agreement": "4/4",
       "top_features": ["reason_code", "frame_rate", "victim_count"]
     }
     ```

3. POST /predict/batch endpoint
4. GET /health endpoint
5. GET /model-info endpoint

6. Feature tracking:
   - Maintain sliding window (last 60 seconds) per source MAC
   - Use dictionary keyed by source MAC
   - Clean up entries older than 5 minutes

7. Run on port 5000 with CORS enabled
8. Add logging for every prediction
9. Handle errors gracefully

requirements.txt:
```
fastapi, uvicorn, joblib, scikit-learn, xgboost, numpy, pandas, pydantic
```

---

### COMPONENT 2: Java Backend Layer2Service
File: `Layer2Service.java`

Create a Spring Boot @Service class:
1. Use RestTemplate to call ML microservice at http://localhost:5000/predict
2. Method: analyzeWithML(DetectionRequest request, DetectionResponse layer1Response)
3. Error handling: if ML service is DOWN → log warning, return default (score=0, prediction=UNKNOWN)
4. Timeout: 500ms max
5. Circuit breaker pattern (optional)

---

### COMPONENT 3: Update Detection Pipeline
File: `DetectionService.java` (update existing)

```java
public void processPacket(DeauthPacketDTO packet) {
    // Step 1: Layer 1 Analysis
    DetectionResponse l1 = layer1Service.analyze(request);
    
    // Step 2: Decide if ML needed
    boolean needsML = l1.getCombinedScore() >= 10 && isDeauthFrame(packet);
    
    int mlScore = 0;
    String mlPrediction = "SKIPPED";
    double mlConfidence = 0.0;
    
    if (needsML) {
        Layer2Response l2 = layer2Service.analyzeWithML(request, l1);
        mlScore = l2.getMlScore();
        mlPrediction = l2.getPrediction();
        mlConfidence = l2.getConfidence();
    }
    
    // Step 4: Final score = L1(30%) + L2(50%) + L3(20%)
    int finalScore = (int)(l1.getCombinedScore() * 0.30 + mlScore * 0.50 + 0 * 0.20);
    
    // Step 5: Save to database
    if (finalScore >= 10) {
        DetectionEvent event = DetectionEvent.builder()
            .attackerMac(packet.getSrc())
            .targetMac(packet.getDst())
            .targetBssid(packet.getBssid())
            .layer1Score(l1.getCombinedScore())
            .layer2Score(mlScore)
            .mlConfidence(mlConfidence)
            .mlPrediction(mlPrediction)
            .totalScore(finalScore)
            .severity(determineSeverity(finalScore))
            .detectedAt(LocalDateTime.now())
            .build();
        eventRepository.save(event);
    }
}
```

---

### COMPONENT 4: Update DetectionEvent Entity
File: `DetectionEvent.java` (update existing)

```java
@Column(name = "layer2_score")
private Integer layer2Score;

@Column(name = "ml_confidence") 
private Double mlConfidence;

@Column(name = "ml_prediction")
private String mlPrediction;

@Column(name = "model_agreement")
private String modelAgreement;
```

---

### COMPONENT 5: Update Frontend
File: `DetectionFeed.tsx` (update existing)

- Show "Layer 1: 35/95 | ML: 92/100 | Final: 67/100"
- Show ML confidence bar
- Show model agreement "4/4 models agree"
- Color code: if ML says Attack with >90% → red, Normal >90% → green, uncertain 50-75% → yellow

---

### COMPONENT 6: Docker Setup (Optional)
File: `docker-compose.yml`

```yaml
version: '3.8'
services:
  ml-service:
    build: ./ml-service
    ports:
      - "5000:5000"
    volumes:
      - ./saved_models:/app/saved_models
```

---

## FILE STRUCTURE

```
project/
├── ml-service/
│   ├── ml_service.py
│   ├── requirements.txt
│   ├── Dockerfile
│   └── saved_models/
│       ├── random_forest_model.pkl
│       ├── xgboost_model.pkl
│       ├── logistic_regression_model.pkl
│       ├── decision_tree_model.pkl
│       ├── standard_scaler.pkl
│       └── feature_names.json
│
├── wifi-security-backend/
│   └── src/main/java/com/wifi/security/
│       ├── service/
│       │   ├── layer1/Layer1Service.java (existing)
│       │   ├── layer2/Layer2Service.java ← NEW
│       │   └── DetectionService.java (update)
│       └── entity/
│           └── DetectionEvent.java (update)
│
└── wifi-security-frontend/
    └── src/components/
        └── DetectionFeed.tsx (update)
```

## HOW TO RUN

```bash
Terminal 1: make run-ml       # Python ML FastAPI service
Terminal 2: make run-backend  # Spring Boot backend
Terminal 3: make run-frontend # React dashboard
Terminal 4: make run-sniffer  # Packet capture
Terminal 5: make run_attack   # Attack testing
```

## TESTING SCENARIOS

| Test | Command | Expected |
|------|---------|----------|
| Flood Attack | `make run_attack` | L1=85, ML=95, Final=90 → CRITICAL |
| Slow Attack | `make bypass_attack` | L1=8, ML=88, Final=47 → MEDIUM/HIGH |
| No Attack | (normal traffic) | L1=0, ML=5, Final=2 → SAFE |
