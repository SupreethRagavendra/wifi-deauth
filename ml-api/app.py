import os
import joblib
import numpy as np
import pandas as pd
import time
import pickle
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
# Use abspath to correctly resolve relative paths even if run from different cwd
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, 'saved_models')
EXPECTED_FEATURES = 13

# Model Storage
models = {
    "decision_tree": None,
    "random_forest": None,
    "logistic_regression": None,
    "xgboost": None,
    "scaler": None
}

# Voting Weights
WEIGHTS = {
    "decision_tree": 0.20,
    "random_forest": 0.30,
    "logistic_regression": 0.20,
    "xgboost": 0.30
}

def load_models():
    """Load all models from disk"""
    print(f"Loading models from: {MODELS_DIR}")
    
    # Map internal names to filenames
    files = {
        "decision_tree": "decision_tree_model.pkl",
        "random_forest": "random_forest_model.pkl",
        "logistic_regression": "logistic_regression_model.pkl",
        "xgboost": "xgboost_model.pkl",
        "scaler": "standard_scaler.pkl"
    }

    loaded_count = 0
    for name, filename in files.items():
        filepath = os.path.join(MODELS_DIR, filename)
        try:
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    models[name] = pickle.load(f)
                print(f"  ✅ Loaded {name}")
                loaded_count += 1
            else:
                print(f"  ❌ File not found: {filename}")
        except Exception as e:
            print(f"  ❌ Failed to load {name}: {e}")
            # Try joblib as fallback
            try:
                models[name] = joblib.load(filepath)
                print(f"  ✅ Loaded {name} (via joblib fallback)")
                loaded_count += 1
            except Exception as e2:
                 print(f"  ❌ Failed to load {name} (joblib fallback): {e2}")

    print(f"Model loading complete. {loaded_count}/{len(files)} loaded.")

# Initialize models on startup
load_models()

def adjust_features(features):
    """Ensure features are exactly 13 elements"""
    if len(features) == EXPECTED_FEATURES:
        return features
    
    if len(features) > EXPECTED_FEATURES:
        # Truncate
        return features[:EXPECTED_FEATURES]
    else:
        # Pad with zeros
        return features + [0] * (EXPECTED_FEATURES - len(features))

@app.route('/health', methods=['GET'])
def health_check():
    status = {
        "status": "healthy",
        "models_loaded": {k: (v is not None) for k, v in models.items()},
        "expected_features": EXPECTED_FEATURES
    }
    return jsonify(status), 200

@app.route('/predict', methods=['POST'])
def predict():
    start_time = time.time()
    
    if not models['scaler']:
        return jsonify({"error": "Scaler not loaded"}), 503

    try:
        data = request.json
        features = data.get('features')
        
        if not features or not isinstance(features, list):
             return jsonify({"error": "Invalid features format. Expected list."}), 400

        # Fix feature count (Java sends 14, models want 13)
        features = adjust_features(features)
        
        # Reshape for scaler
        features_array = np.array(features).reshape(1, -1)
        
        # Scale
        features_scaled = models['scaler'].transform(features_array)
        
        # Get votes
        votes = {}
        weighted_score = 0.0
        total_weight = 0.0
        
        for name, model in models.items():
            if name == 'scaler' or model is None:
                continue
                
            try:
                # Predict class (0 or 1)
                prediction = model.predict(features_scaled)[0]
                votes[name] = int(prediction)
                
                # Add weighted score
                weight = WEIGHTS.get(name, 0.0)
                weighted_score += prediction * weight
                total_weight += weight
                
            except Exception as e:
                print(f"Error predicting with {name}: {e}")
                votes[name] = -1 # Error code
        
        # Normalize score if some models failed
        final_confidence = 0.0
        if total_weight > 0:
            final_confidence = (weighted_score / total_weight) * 100
            
        final_prediction = 1 if final_confidence > 50 else 0
        verdict = "ATTACK" if final_prediction == 1 else "NORMAL"
        
        processing_time = (time.time() - start_time) * 1000
        
        response = {
            "prediction": final_prediction,
            "verdict": verdict,
            "confidence": round(final_confidence, 2),
            "model_votes": votes,
            "processing_time_ms": round(processing_time, 2),
            # Backwards compatibility fields for Java
            "details": {k: float(v) for k,v in votes.items()} 
        }
        
        return jsonify(response), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/test-predict', methods=['GET'])
def test_predict():
    """Run a dummy prediction for testing"""
    dummy_features = [0] * 14 # Intentionally 14 to test adjustment
    
    # Mock request
    with app.test_request_context(json={"features": dummy_features}):
        return predict()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
