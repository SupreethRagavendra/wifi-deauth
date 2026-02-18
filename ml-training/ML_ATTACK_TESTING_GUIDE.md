# 🛡️ ML Model Testing Guide: Which Attack Tests Which Model?

Use this guide to verify if your models are actually learning useful patterns.

---

## 1. The "Hammer" Test (High-Rate Deauth Flood)
**Target Model:** 🌳 **Decision Tree** (and Logistic Regression)
**Scenario:** An attacker screams deauth packets as fast as possible (100+ frames/sec).
*   **Why:** This is a simple, linear attack. A Decision Tree loves this because it can make one easy split: `IF frame_rate > 50 THEN ATTACK`.
*   **Expected Result:**
    *   **Decision Tree:** ✅ **100% Detection** (Very confident)
    *   **Logistic Regression:** ✅ **High Detection**
    *   **XGBoost:** ✅ **High Detection**
*   **Key Features:** `frame_rate` (High), `mean_interval` (Tiny)

---

## 2. The "Ninja" Test (Low-and-Slow)
**Target Model:** 🌲 **Random Forest**
**Scenario:** The attacker sends 1 packet every few seconds. It looks like normal management traffic to a simple firewall.
*   **Why:** A simple Decision Tree might say "Rate is low, must be Safe." Random Forest is smarter—it looks at **combinations**. It sees: "Rate is low... BUT the sequence number is jumping... AND the signal strength is weird. VOTE ATTACK."
*   **Expected Result:**
    *   **Decision Tree:** ❌ **Might Miss it** (False Negative)
    *   **Random Forest:** ✅ **Detects it** (Finds the subtle pattern combo)
*   **Key Features:** `seq_variance` (High), `rssi_delta` (Medium), `time_since_legit` (Short)

---

## 3. The "Imposter" Test (Sequence Spoofing)
**Target Model:** 🚀 **XGBoost**
**Scenario:** The attacker tries to fake the Access Point, but their hardware injects random sequence numbers (1, 1000, 5, 200...) instead of 1, 2, 3, 4.
*   **Why:** XGBoost is the "Math Whiz." It is excellent at catching complex numerical anomalies that don't fit a standard curve. It will see the mathematical impossibility of the sequence gaps.
*   **Expected Result:**
    *   **Logistic Regression:** ❌ **Misses it** (Can't see non-linear patterns)
    *   **XGBoost:** ✅ **High Confidence** (The sequence variance heavily penalizes the score)
*   **Key Features:** `seq_variance` (Massive), `rssi` (Mismatched)

---

## 4. The "Evil Twin" Test (Signal Anomaly)
**Target Model:** 🌲 **Random Forest / XGBoost**
**Scenario:** The attacker is sitting in the parking lot (-80 dBm), while the real AP is in the office (-40 dBm). The packets fluctuate wildly in signal strength.
*   **Why:** This is a physical layer anomaly. Logical models (checking only packet headers) will fail. Trees that use `rssi` and `rssi_delta` as splits will catch this sudden change in the environment.
*   **Features:** `rssi_delta` (High), `rssi` (Low/Different)

---

## 🧪 Summary Table for Your Report

| Attack Type | Best Model to Detect | Main Feature Clue |
| :--- | :--- | :--- |
| **Flood (Simple)** | Decision Tree / LR | `frame_rate` (Speed) |
| **Stealth (Slow)** | Random Forest | `mean_interval` + `seq_variance` |
| **Spoofing (Complex)** | XGBoost | `seq_variance` (Gaps) |
| **Signal Hopping** | Random Forest | `rssi_delta` (Signal Jumps) |
