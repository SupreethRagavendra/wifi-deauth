import pandas as pd
import numpy as np
import random
import time
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import xgboost as xgb
import matplotlib.pyplot as plt
import seaborn as sns

# ==========================================
# 1. SETUP & CONFIGURATION
# ==========================================
# Create models directory
if not os.path.exists('models'):
    os.makedirs('models')

print("🚀 STARTING ML TRAINING PIPELINE")
print("==================================")

# ==========================================
# 2. DATA GENERATION (Synthetic)
# ==========================================
print("\n[STEP 1] Generating Synthetic Dataset...")

np.random.seed(42)
random.seed(42)

def generate_normal_sample():
    """Generate features for normal traffic"""
    return {
        'frame_rate': round(random.uniform(0.5, 5.0), 2),
        'seq_variance': round(random.uniform(1, 20), 2),
        'mean_interval': round(random.uniform(0.1, 1.0), 2),
        'std_interval': round(random.uniform(0.05, 0.2), 3),
        'rssi': random.randint(-60, -40),
        'rssi_delta': random.randint(-5, 5),
        'hour': random.choice([8,9,10,11,12,13,14,15,16,17,18]),
        'day_of_week': random.randint(1, 5),
        'victim_count': 1,
        'reason_code': random.choice([1, 3, 8]),
        'time_since_legit': random.randint(1800, 7200),
        'assoc_duration': random.randint(60, 600),
        'throughput': random.randint(500, 2000),
        'channel': random.choice([1, 6, 11]),
        'label': 0  # NORMAL
    }

def generate_attack_sample():
    """Generate features for attack traffic"""
    return {
        'frame_rate': round(random.uniform(15, 100), 2),
        'seq_variance': round(random.uniform(200, 2000), 2),
        'mean_interval': round(random.uniform(0.001, 0.05), 3),
        'std_interval': round(random.uniform(0.001, 0.01), 4),
        'rssi': random.randint(-90, -70),
        'rssi_delta': random.randint(-25, -10),
        'hour': random.choice([0,1,2,3,22,23] + list(range(8,18))),
        'day_of_week': random.randint(0, 6),
        'victim_count': random.randint(2, 10),
        'reason_code': 7,
        'time_since_legit': random.randint(3600, 14400),
        'assoc_duration': random.randint(1, 180),
        'throughput': random.randint(1000, 5000),
        'channel': random.choice([1, 6, 11]),
        'label': 1  # ATTACK
    }

# Generate 5000 normal and 5000 attack samples
normal_samples = [generate_normal_sample() for _ in range(5000)]
attack_samples = [generate_attack_sample() for _ in range(5000)]
all_samples = normal_samples + attack_samples
random.shuffle(all_samples)

df = pd.DataFrame(all_samples)
print(f"✅ Generated {len(df)} samples (Balanced 50/50)")

# Save Raw Data
df.to_csv('models/training_data.csv', index=False)
print("💾 Saved raw data to models/training_data.csv")


# ==========================================
# 3. PREPROCESSING
# ==========================================
print("\n[STEP 2] Preprocessing Data...")

X = df.drop('label', axis=1)
y = df['label']

# Split: 80% Train, 20% Test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Fit Standard Scaler
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Save Scaler
joblib.dump(scaler, 'models/scaler.pkl')
joblib.dump(X.columns.tolist(), 'models/feature_names.pkl')
print("✅ Data Scaled and Scaler saved")


# ==========================================
# 4. MODEL TRAINING
# ==========================================
print("\n[STEP 3] Training Models...")

models = {
    "Decision Tree": DecisionTreeClassifier(max_depth=10, random_state=42),
    "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42),
    "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
    "XGBoost": xgb.XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42)
}

trained_models = {}
results = {}

for name, model in models.items():
    print(f"   ⏳ Training {name}...")
    start_time = time.time()
    
    # Train
    model.fit(X_train_scaled, y_train)
    
    # Predict
    y_pred = model.predict(X_test_scaled)
    
    # Metrics
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    
    elapsed = time.time() - start_time
    
    results[name] = {
        "Accuracy": acc,
        "F1 Score": f1,
        "Recall": recall,
        "Time": elapsed
    }
    
    trained_models[name] = model
    
    # Save Model
    filename = f"models/{name.lower().replace(' ', '_')}.pkl"
    joblib.dump(model, filename)
    print(f"      ✅ Accuracy: {acc*100:.2f}% | Saved to {filename}")

# ==========================================
# 5. EVALUATION REPORT
# ==========================================
print("\n[STEP 4] Evaluation Report")
print("-" * 65)
print(f"{'Model':<20} | {'Accuracy':<10} | {'Recall':<10} | {'F1 Score':<10}")
print("-" * 65)

for name, metrics in results.items():
    print(f"{name:<20} | {metrics['Accuracy']*100:.2f}%     | {metrics['Recall']*100:.2f}%     | {metrics['F1 Score']*100:.2f}%")

print("-" * 65)
print("🚀 Training Complete! All artifacts in 'models/' directory.")
