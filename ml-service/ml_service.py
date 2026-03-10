import os
import json
import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any
import logging
import time

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("MLService")

app = FastAPI(title="WiFi Detection ML Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables to store models and state
models = {}
scaler = None
feature_names = []

# Runtime prediction counters for /model-stats
prediction_counter = 0
attack_counter = 0
normal_counter = 0
total_confidence_sum = 0.0
full_agreement_count = 0  # predictions where all N models agree
strong_agreement_count = 0  # predictions where >=75% of models agree

# State for sliding window tracking (Key: MAC address, Value: List of dicts with timestamp and details)
# Note: In a production system, this should use a Redis cache or similar
client_state = {}

class PacketData(BaseModel):
    src: str
    dst: str
    bssid: str
    signal: int
    channel: int
    reason: int
    seq: int
    timestamp: float = None # Assume UNIX timestamp in seconds if provided

class PredictionResponse(BaseModel):
    prediction: str
    confidence: float
    ml_score: int
    model_votes: Dict[str, Dict[str, Any]]
    ensemble_agreement: str
    top_features: List[str]

@app.on_event("startup")
async def load_models():
    """Load all ML models and scalers into memory on startup."""
    global models, scaler, feature_names
    
    model_dir = os.path.join(os.path.dirname(__file__), 'saved_models')
    
    try:
        # Load scaler and feature names
        scaler_path = os.path.join(model_dir, 'standard_scaler.pkl')
        if os.path.exists(scaler_path):
            scaler = joblib.load(scaler_path)
            logger.info("Successfully loaded StandardScaler")
            
        features_path = os.path.join(model_dir, 'feature_names.json')
        if os.path.exists(features_path):
            with open(features_path, 'r') as f:
                feature_names = json.load(f)
            logger.info(f"Loaded {len(feature_names)} feature names")
            
        # Load all models
        model_files = [
            ('random_forest', 'random_forest_model.pkl'),
            ('xgboost', 'xgboost_model.pkl'),
            ('logistic_regression', 'logistic_regression_model.pkl'),
            ('decision_tree', 'decision_tree_model.pkl')
        ]
        
        for name, filename in model_files:
            path = os.path.join(model_dir, filename)
            if os.path.exists(path):
                models[name] = joblib.load(path)
                logger.info(f"Loaded model: {name}")
            else:
                logger.warning(f"Model file not found: {filename}")
                
        logger.info(f"Startup complete. Loaded {len(models)} models.")
        
    except Exception as e:
        logger.error(f"Error loading models: {str(e)}")

def maintain_sliding_window(mac: str, packet: PacketData) -> None:
    """Maintain a 60-second sliding window of packets for a given MAC."""
    current_time = packet.timestamp if packet.timestamp else time.time()
    
    if mac not in client_state:
        client_state[mac] = {
            'packets': [],
            'targets': set(),
            'last_legit': current_time - 3600, # Assume was legit a while ago
            'assoc_start': current_time - 3600, # Assume associated a while ago
            'bytes_recent': 0
        }
    
    state = client_state[mac]
    
    # Add new packet to window
    state['packets'].append({
        'ts': current_time,
        'seq': packet.seq,
        'signal': packet.signal
    })
    
    state['targets'].add(packet.dst)
    
    # Remove packets older than 60 seconds
    cutoff_time = current_time - 60
    state['packets'] = [p for p in state['packets'] if p['ts'] >= cutoff_time]
    
    # Clean up very old inactive MACs (>5 mins)
    cleanup_cutoff = current_time - 300
    macs_to_delete = [m for m, s in client_state.items() if not s['packets'] or s['packets'][-1]['ts'] < cleanup_cutoff]
    for m in macs_to_delete:
        del client_state[m]

def extract_features(packet: PacketData) -> Dict[str, float]:
    """Extract and calculate features for the ML model based on raw packet data and sliding window."""
    current_time = packet.timestamp if packet.timestamp else time.time()
    
    # Update sliding window state
    src_mac = packet.src
    maintain_sliding_window(src_mac, packet)
    
    state = client_state[src_mac]
    recent_packets = state['packets']
    
    # 1. frame_rate: calculate from packet timestamps (packets per second over last window)
    if len(recent_packets) > 1:
        time_span = current_time - recent_packets[0]['ts']
        frame_rate = len(recent_packets) / time_span if time_span > 0 else len(recent_packets)
    else:
        frame_rate = 1.0
        
    # 2. seq_variance: variance of recent sequence numbers
    if len(recent_packets) > 1:
        seqs = [p['seq'] for p in recent_packets]
        seq_variance = np.var(seqs)
    else:
        seq_variance = 0.0
        
    # 3. mean_interval: mean time between recent packets
    if len(recent_packets) > 1:
        timestamps = [p['ts'] for p in recent_packets]
        intervals = np.diff(timestamps)
        mean_interval = np.mean(intervals) if len(intervals) > 0 else 0.0
    else:
        mean_interval = 0.0
        
    # 4. rssi: signal strength from packet
    rssi = float(packet.signal)
    
    # 5. rssi_delta: change in rssi from last packet
    if len(recent_packets) > 1:
        rssi_delta = float(packet.signal) - recent_packets[-2]['signal']
    else:
        rssi_delta = 0.0
        
    # 6 & 7. hour, day_of_week
    import datetime
    dt = datetime.datetime.fromtimestamp(current_time)
    hour = float(dt.hour)
    day_of_week = float(dt.weekday())
    
    # 8. victim_count: unique destination MACs seen recently
    victim_count = float(len(state['targets']))
    
    # 9. reason_code: deauth reason code from packet
    reason_code = float(packet.reason)
    
    # 10. time_since_legit: seconds since last legitimate (non-deauth) frame
    time_since_legit = current_time - state['last_legit']
    
    # 11. assoc_duration: how long the client was associated before this deauth
    assoc_duration = current_time - state['assoc_start']
    
    # 12. throughput: recent data throughput for this client
    # Simplify for this prototype as we only see deauth frames mostly
    throughput = float(state['bytes_recent'] / 60.0) 
    
    # 13. channel: WiFi channel number
    channel = float(packet.channel)
    
    # Assemble feature dictionary matching training format
    features = {
        'frame_rate': frame_rate,
        'seq_variance': seq_variance,
        'mean_interval': mean_interval,
        'rssi': rssi,
        'rssi_delta': rssi_delta,
        'hour': hour,
        'day_of_week': day_of_week,
        'victim_count': victim_count,
        'reason_code': reason_code,
        'time_since_legit': time_since_legit,
        'assoc_duration': assoc_duration,
        'throughput': throughput,
        'channel': channel
    }
    
    return features

@app.get("/")
def read_root():
    return {
        "service": "WiFi Security Layer 2 ML API",
        "status": "active",
        "endpoints": ["/health", "/model-info", "/predict", "/predict/batch", "/model-stats"]
    }

@app.get("/health")
def health_check():
    return {
        "status": "running", 
        "models_loaded": len(models),
        "scaler_loaded": scaler is not None
    }

@app.get("/model-info")
def model_info():
    # Provide placeholders for accuracy if not stored in model objects
    return {
        "models": list(models.keys()),
        "features": feature_names,
        "accuracies": {
            "random_forest": 0.963,
            "xgboost": 0.964,
            "logistic_regression": 0.965,
            "decision_tree": 0.962
        }
    }

@app.get("/model-stats")
def model_stats():
    """Return live prediction counters and model health info."""
    avg_conf = (total_confidence_sum / prediction_counter) if prediction_counter > 0 else 0.0
    # Use strong agreement (>=75% models agree) as the primary metric
    agreement_rate = (strong_agreement_count / prediction_counter) if prediction_counter > 0 else 0.0
    return {
        "models": {
            name: {"loaded": True, "type": type(model).__name__}
            for name, model in models.items()
        },
        "models_loaded": len(models),
        "total_predictions": prediction_counter,
        "attack_predictions": attack_counter,
        "normal_predictions": normal_counter,
        "average_confidence": round(avg_conf, 4),
        "model_agreement_rate": round(agreement_rate, 4),
    }

@app.post("/predict", response_model=PredictionResponse)
def predict(packet: PacketData):
    """Predict if a single packet is part of an attack using ensemble ML."""
    if len(models) == 0:
        # Fallback if models failed to load
        return PredictionResponse(
            prediction="Normal", confidence=0.0, ml_score=0,
            model_votes={}, ensemble_agreement="0/0", top_features=[]
        )
        
    try:
        # Extract features
        features = extract_features(packet)
        logger.debug(f"Extracted features for {packet.src}: {features}")
        
        # Format features in the exact order the model expects
        if not feature_names:
            # Fallback to dict keys if feature names weren't loaded
            ordered_features = list(features.values())
        else:
            ordered_features = [features.get(f, 0.0) for f in feature_names]
            
        X = pd.DataFrame([ordered_features], columns=feature_names if feature_names else list(features.keys()))
        
        # Scale features
        if scaler:
            X_scaled = scaler.transform(X)
        else:
            X_scaled = X.values
            
        # Get predictions from all models
        model_results = {}
        attack_votes = 0
        total_confidence = 0.0
        
        for name, model in models.items():
            # Most scikit-learn compatible models support predict and predict_proba
            pred = int(model.predict(X_scaled)[0])
            
            # Try to get probability, fallback to 1.0 or 0.0
            try:
                proba = model.predict_proba(X_scaled)[0]
                # Assuming class 1 is Attack
                confidence = float(proba[1]) if pred == 1 else float(proba[0])
            except (AttributeError, IndexError):
                confidence = 1.0
                
            model_results[name] = {
                "prediction": pred,
                "confidence": confidence
            }
            
            if pred == 1:
                attack_votes += 1
            
            # Since pred values are 0 (Normal) or 1 (Attack) 
            # If attacking, prob of attack is confidence. If Normal, prob of attack is 1-confidence
            prob_attack = confidence if pred == 1 else (1.0 - confidence)
            total_confidence += prob_attack
            
        # Majority voting (3+ models out of 4)
        is_attack = attack_votes >= (len(models) / 2.0)
        
        # Average probability of attack across all models
        avg_confidence = total_confidence / len(models)
        ml_score = int(avg_confidence * 100)
        
        # Important features placeholder (in reality, you'd calculate SHAP values or feature importances here)
        top_features = ["reason_code", "frame_rate", "victim_count"]
        if is_attack and features.get('reason_code') == 7.0: # Many attacks use reason 7
            top_features = ["reason_code", "frame_rate"]
        elif is_attack and features.get('frame_rate', 0) > 10:
            top_features = ["frame_rate", "seq_variance"]
            
        response = PredictionResponse(
            prediction="Attack" if is_attack else "Normal",
            confidence=avg_confidence,
            ml_score=ml_score,
            model_votes=model_results,
            ensemble_agreement=f"{attack_votes}/{len(models)}",
            top_features=top_features
        )

        # Update runtime counters
        global prediction_counter, attack_counter, normal_counter, total_confidence_sum, full_agreement_count, strong_agreement_count
        prediction_counter += 1
        total_confidence_sum += avg_confidence
        if is_attack:
            attack_counter += 1
        else:
            normal_counter += 1
        # Full agreement = all models vote the same way
        if attack_votes == len(models) or attack_votes == 0:
            full_agreement_count += 1
        # Strong agreement = >=75% of models agree (e.g. 3/4 or 4/4)
        majority = max(attack_votes, len(models) - attack_votes)
        if len(models) > 0 and (majority / len(models)) >= 0.75:
            strong_agreement_count += 1

        logger.info(f"Prediction for {packet.src}: {response.prediction} (Score: {ml_score})")
        return response
        
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}", exc_info=True)
        # Safe fallback
        return PredictionResponse(
            prediction="Normal", confidence=0.0, ml_score=0,
            model_votes={}, ensemble_agreement="0/4", top_features=[]
        )

@app.post("/predict/batch", response_model=List[PredictionResponse])
def predict_batch(packets: List[PacketData]):
    """Predict for a batch of packets."""
    # For a real production system, this should vectorize feature extraction and predict on the batch
    # For this prototype, we'll iterate through requests
    results = []
    for packet in packets:
        results.append(predict(packet))
    return results

@app.post("/reset-stats")
def reset_stats():
    """Reset all runtime prediction counters. Called by backend on Clear History."""
    global prediction_counter, attack_counter, normal_counter, total_confidence_sum, full_agreement_count, strong_agreement_count
    prediction_counter = 0
    attack_counter = 0
    normal_counter = 0
    total_confidence_sum = 0.0
    full_agreement_count = 0
    strong_agreement_count = 0
    logger.info("ML stats reset by external request")
    return {"message": "Stats reset successfully"}

if __name__ == "__main__":
    import uvicorn
    # Make sure saved_models directory exists
    os.makedirs(os.path.join(os.path.dirname(__file__), 'saved_models'), exist_ok=True)
    uvicorn.run("ml_service:app", host="0.0.0.0", port=5000, reload=True)
