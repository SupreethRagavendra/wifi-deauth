
import os
import joblib
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Load models at startup
try:
    print("Loading models...")
    MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
    
    dt_model = joblib.load(os.path.join(MODELS_DIR, 'decision_tree.pkl'))
    rf_model = joblib.load(os.path.join(MODELS_DIR, 'random_forest.pkl'))
    lr_model = joblib.load(os.path.join(MODELS_DIR, 'logistic_regression.pkl'))
    xgb_model = joblib.load(os.path.join(MODELS_DIR, 'xgboost.pkl'))
    scaler = joblib.load(os.path.join(MODELS_DIR, 'scaler.pkl'))
    
    print("✅ All models loaded successfully!")
except Exception as e:
    print(f"❌ Failed to load models: {str(e)}")
    print("Ensure models are in the 'models/' directory.")
    dt_model = rf_model = lr_model = xgb_model = scaler = None

@app.route('/health', methods=['GET'])
def health_check():
    status = "healthy" if dt_model else "models_missing"
    return jsonify({"status": status, "service": "wifi-security-ml-api"}), 200

@app.route('/predict', methods=['POST'])
def predict():
    if not dt_model:
        return jsonify({"error": "Models not loaded"}), 503

    try:
        data = request.json
        features = data.get('features') # Expecting list of feature values
        
        if not features or len(features) != 14:
             return jsonify({"error": "Invalid features. Expected 14 values."}), 400

        # Convert to DataFrame for scaler (needs feature names sometimes, but array works for transform)
        # Using DataFrame with dummy columns to silence warnings if scaler was fitted on DF
        # Or just reshape
        features_array = np.array(features).reshape(1, -1)
        
        # Scale features
        # Note: Scaler expects 14 features
        features_scaled = scaler.transform(features_array)
        
        # Get predictions
        dt_prob = dt_model.predict_proba(features_scaled)[0][1]
        rf_prob = rf_model.predict_proba(features_scaled)[0][1]
        lr_prob = lr_model.predict_proba(features_scaled)[0][1]
        xgb_prob = xgb_model.predict_proba(features_scaled)[0][1]
        
        # Weighted Ensemble Voting (Matches Java logic)
        # 20% DT, 30% RF, 20% LR, 30% XGB
        ensemble_score = (dt_prob * 0.2) + (rf_prob * 0.3) + (lr_prob * 0.2) + (xgb_prob * 0.3)
        ensemble_confidence = ensemble_score * 100
        
        verdict = "ATTACK" if ensemble_confidence > 75 else "NORMAL"
        
        response = {
            "verdict": verdict,
            "confidence": round(ensemble_confidence, 2),
            "details": {
                "decision_tree": round(dt_prob * 100, 2),
                "random_forest": round(rf_prob * 100, 2),
                "logistic_regression": round(lr_prob * 100, 2),
                "xgboost": round(xgb_prob * 100, 2)
            }
        }
        
        return jsonify(response), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
