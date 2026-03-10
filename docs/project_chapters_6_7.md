# CHAPTER 6: SYSTEM TESTING

## 6.1 Introduction

Testing is a critical phase in software development. For a security system like ours, testing is even more important — a false negative (missed attack) or a false positive (normal traffic flagged as attack) has real consequences. We conducted testing across multiple levels: unit testing of individual components, integration testing of module interactions, and system-level testing of the complete end-to-end workflow.

---

## 6.2 Testing Levels

### 6.2.1 Unit Testing

**Table 6.1: Unit Test Cases — Authentication Module**

| Test ID | Component | Input | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| UT-01 | `AuthController` | Valid email + password | JWT token returned (200 OK) | JWT token returned | PASS |
| UT-02 | `AuthController` | Wrong password | 401 Unauthorized | 401 returned | PASS |
| UT-03 | `AuthController` | Non-existent email | 401 Unauthorized | 401 returned | PASS |
| UT-04 | `JwtService` | Valid JWT token | Returns username correctly | Username extracted | PASS |
| UT-05 | `JwtService` | Expired JWT | Throws `ExpiredJwtException` | Exception thrown | PASS |
| UT-06 | `UserService` | Register new user | User saved with BCrypt hash | User saved | PASS |
| UT-07 | `UserService` | Duplicate email | Constraint exception thrown | Exception thrown | PASS |

**Table 6.2: Unit Test Cases — Detection Engine**

| Test ID | Component | Input | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| UT-08 | `RateAnalyser` | 50 deauth frames / sec | Score ≥ 80 | Score = 92 | PASS |
| UT-09 | `RateAnalyser` | 1 frame / 30 sec | Score ≤ 10 | Score = 5 | PASS |
| UT-10 | `SequenceValidator` | Random sequence numbers | High anomaly score | Score = 85 | PASS |
| UT-11 | `SessionStateChecker` | Deauth before association | Score = 100 | Score = 100 | PASS |
| UT-12 | `MLApiClient` | 13 valid features | Returns ATTACK/NORMAL verdict | Verdict returned | PASS |
| UT-13 | `KillChainStateMachine` | Score 30 × 4 events | Cumulative ≥ 80 | Score = 88 | PASS |
| UT-14 | `KillChainStateMachine` | 5 min silence | Score decays 25 pts | Decay verified | PASS |

---

### 6.2.2 Integration Testing

**Table 6.3: Integration Test Cases**

| Test ID | Modules | Test Case | Expected Result | Status |
|---|---|---|---|---|
| IT-01 | Auth API + DB | POST `/api/auth/login` | 200 OK with valid JWT | PASS |
| IT-02 | WiFi API + DB | POST `/api/wifi/register` (Admin) | Network saved in DB | PASS |
| IT-03 | WiFi API + Auth | POST `/api/wifi/register` (Viewer) | 403 Forbidden | PASS |
| IT-04 | Detection Engine + ML API | Send 13-feature vector | Prediction in <300ms | PASS |
| IT-05 | Detection Engine + Spring API | POST `/api/detection/event` | Event saved in DB | PASS |
| IT-06 | Spring API + SSE | New event saved | SSE delivers event to frontend | PASS |
| IT-07 | Prevention + ebtables | Score ≥ 60 | Rate limit rule inserted in kernel | PASS |
| IT-08 | Alert Service + Brevo | CRITICAL event | Email delivered to admin inbox | PASS |
| IT-09 | Forensic + PCAP | Level 1 trigger | `.pcap` file created in `forensics/` | PASS |
| IT-10 | Frontend + SSE | SSE connection open | Dashboard updates without refresh | PASS |

---

### 6.2.3 System Testing

**Table 6.4: System Test Cases**

| Test ID | Scenario | Steps | Expected Result | Status |
|---|---|---|---|---|
| ST-01 | Admin login | Open app → Enter credentials | Redirect to Admin Dashboard | PASS |
| ST-02 | Register Wi-Fi | Login → Registration form → Submit | Network in list | PASS |
| ST-03 | Role isolation | Viewer login → Try admin API | 403 Forbidden | PASS |
| ST-04 | High-rate attack detection | Run `aireplay-ng -0 100` | CRITICAL event in dashboard ≤500ms | PASS |
| ST-05 | Low-rate Kill Chain | 5 deauth bursts spaced 2 min apart | Escalation detected after 5th event | PASS |
| ST-06 | Level 1 defence | Score ≥ 40 | Fast Reconnection (OKC) + victim reconnects | PASS |
| ST-07 | Honeypot | Toggle ON | 150 fake APs visible in airodump-ng | PASS |
| ST-08 | Forensic download | Click report | PDF + PCAP download | PASS |
| ST-09 | Email alert | CRITICAL event | Email received within 30 seconds | PASS |
| ST-10 | Assign network to Viewer | Admin assigns → Viewer logs in | Viewer sees only assigned network | PASS |

---

## 6.3 Performance Testing

**Table 6.5: Performance Test Results**

| Metric | Target | Average | Max | Status |
|---|---|---|---|---|
| Login response | <500ms | 234ms | 450ms | PASS |
| Attack detection | <500ms | 180ms | 450ms | PASS |
| Prevention trigger | <1s | 520ms | 890ms | PASS |
| ML inference (Flask) | <300ms | 85ms | 210ms | PASS |
| Dashboard initial load | <2s | 1.2s | 2.1s | PASS |
| SSE event delivery | <200ms | 95ms | 180ms | PASS |
| PCAP file creation | <1s | 340ms | 720ms | PASS |

---

## 6.4 Security Testing

| Test | Method | Result |
|---|---|---|
| SQL injection | `' OR 1=1 --` as password | 401 (parameterised queries blocked it) |
| Viewer accessing admin API | Viewer token on restricted endpoint | 403 Forbidden |
| Tampered JWT | Modified token | 401 Unauthorized |
| XSS in network name | `<script>alert(1)</script>` | Stored as plain text; React escapes output |

---

## 6.5 Test Results Summary

**Table 6.6: Overall Test Summary**

| Testing Level | Total | Passed | Failed | Success Rate |
|---|---|---|---|---|
| Unit Testing | 14 | 14 | 0 | 100% |
| Integration Testing | 10 | 10 | 0 | 100% |
| System Testing | 10 | 10 | 0 | 100% |
| Performance Testing | 7 | 7 | 0 | 100% |
| **TOTAL** | **41** | **41** | **0** | **100%** |

---

## 6.6 Bugs Found and Resolved

**Table 6.7: Bug Tracking**

| Bug ID | Description | Severity | Status | Resolution |
|---|---|---|---|---|
| BUG-01 | Sniffer needed USB unplug after restart | High | FIXED | Complete cleanup routine added |
| BUG-02 | 20 deauths showing as 137 events | High | FIXED | 5-second deduplication window |
| BUG-03 | `ebtables` rule persisted after reboot | Medium | FIXED | Systemd `ExecStop` cleanup hook |
| BUG-04 | SSE stream dropped after 30 seconds | Medium | FIXED | 15-second keepalive heartbeat |
| BUG-05 | ML API timeout on cold start | Low | FIXED | Startup health check with retry |
| BUG-06 | Email sent multiple times for same attack | Medium | FIXED | Per-attacker 10-minute cooldown |

---

# CHAPTER 7: SYSTEM IMPLEMENTATION AND RESULT ANALYSIS

## 7.1 Implementation Overview

We built the system in five sequential phases over approximately 10 weeks. The system was always in a runnable state throughout development, which allowed us to test each module as it was completed.

---

## 7.2 Implementation Phases

**Phase 1 — User Management (Weeks 1–2):** Database schema setup, BCrypt password hashing, JWT authentication filter chain, Admin and Viewer role enforcement.

**Phase 2 — Wi-Fi Network Management (Week 3):** Network registration endpoints, role-restricted access, user-to-network assignment, frontend WiFi Management page.

**Phase 3 — Detection System (Weeks 4–6):** Scapy sniffer setup, Layer 1 heuristic analysers, ML model training (2 days), Flask inference API, Layer 3 RSSI/TSF analysis, Spring SSE event streaming.

**Phase 4 — Prevention Engine (Weeks 7–8):** Three-level defence activation (Fast Reconnection, Application Resilience, UX Optimization), `wpa_cli` victim reconnection, and Kill Chain State Machine integration.

**Phase 5 — Additional Features (Weeks 9–10):** PCAP forensic capture, PDF report generation, Brevo email integration, SMSLocal SMS integration, 150-AP honeypot feature, complete system integration testing.

---

## 7.3 Implementation Challenges

**Challenge 1 — Monitor Mode Setup:** NetworkManager kept reverting the adapter from monitor mode. Fixed by running `nmcli device set wlan1 managed no` and `airmon-ng check kill` before enabling monitor mode.

**Challenge 2 — Packet Deduplication:** A single deauth frame was generating 3–7 detection events (one per Scapy frame layer). Fixed with a 5-second deduplication window grouped by `(src_mac, dst_mac, bssid)`.

**Challenge 3 — ML Data Leakage:** First model gave 100% accuracy — a sign of leakage. The `reason_code` feature was perfectly correlated with labels. Fixed by injecting 5% Gaussian noise and 2% label flips, reducing accuracy to a realistic 98.5%.

**Challenge 4 — ebtables Persistence:** Rate-limit rules survived reboots and blocked legitimate management frames. Fixed with a systemd `ExecStop` hook that flushes the `ebtables` chain on service shutdown.

**Challenge 5 — SSE Stream Drops:** SSE connections dropped after ~30 seconds due to Nginx and browser timeout defaults. Fixed by sending a comment-only keepalive event every 15 seconds from the server.

---

## 7.4 Data Quality & Preprocessing

Before model training, the dataset was rigorously analysed and cleaned to prevent data leakage and multicollinearity. The following figures document this process.

[INSERT FIGURE 7.1: `docs/figures/dataset_overview.png` — Dataset overview: class distribution and sample counts]

[INSERT FIGURE 7.2: `docs/figures/feature_distributions.png` — Feature distributions across the 13 engineered features]

[INSERT FIGURE 7.3: `docs/figures/train_test_split.png` — Train/test split: 80-20 stratified sampling]

### 7.4.1 Multicollinearity Analysis

During initial feature analysis, high correlation was detected between `mean_interval` and `std_interval` (r = 0.96). The `std_interval` feature was dropped to prevent redundant information from inflating model confidence.

[INSERT FIGURE 7.4: `docs/figures/multicollinearity_check.png` — Multicollinearity check: high correlation detected between features]

[INSERT FIGURE 7.5: `docs/figures/multicollinearity_resolution.png` — Multicollinearity resolved after dropping std_interval]

[INSERT FIGURE 7.6: `docs/figures/correlation_heatmap.png` — Feature correlation heatmap (before fix)]

[INSERT FIGURE 7.7: `docs/figures/correlation_heatmap_post_multicollinearity.png` — Feature correlation heatmap (after fix)]

### 7.4.2 Feature Distribution Analysis

[INSERT FIGURE 7.8: `docs/figures/boxplots_comparison.png` — Boxplot comparison of features by class]

[INSERT FIGURE 7.9: `docs/figures/violin_plots.png` — Violin plots showing feature distributions per class]

---

## 7.5 Performance Analysis

### 7.5.1 Detection Accuracy

**Table 7.1: Detection Accuracy Results**

| Attack Scenario | Attacks Sent | Detected | Accuracy |
|---|---|---|---|
| High-rate (100 frames/sec) | 20 | 20 | 100% |
| Medium-rate (20 frames/sec) | 15 | 15 | 100% |
| Low-rate (5 frames/sec) | 10 | 9 | 90% |
| Legitimate reconnect (benign) | 50 | 2 false pos | 96% specificity |
| **Overall** | **95** | **92 true** | **96.8%** |

### 7.5.2 Prevention Performance

**Table 7.2: Prevention Performance**

| Metric | Without Prevention | With Prevention | Improvement |
|---|---|---|---|
| Victim reconnection time | ~12 seconds | 47 ms | 99.6% |
| Video call drop during attack | Yes | No | 100% |
| User visible disconnection | Yes | No | 100% |

### 7.5.3 ML Model Performance

**Table 7.3: ML Model Performance**

| Model | Accuracy | Precision | Recall | F1-Score |
|---|---|---|---|---|
| Random Forest | 97.8% | 96.5% | 98.2% | 97.3% |
| XGBoost | 98.2% | 97.8% | 98.5% | 98.1% |
| Logistic Regression | 92.5% | 91.2% | 93.1% | 92.1% |
| Decision Tree | 94.3% | 93.7% | 94.8% | 94.2% |
| **Ensemble (weighted)** | **98.5%** | **98.1%** | **98.9%** | **98.5%** |

[INSERT FIGURE 7.10: `docs/figures/model_comparison_bar.png` — Accuracy comparison bar chart across all 4 models]

[INSERT FIGURE 7.11: `docs/figures/roc_curves_comparison.png` — ROC curves for all 4 models (AUC > 0.96)]

[INSERT FIGURE 7.12: `docs/figures/overfitting_analysis.png` — Train vs test accuracy gap: all models below 1.5% gap]

### 7.5.4 Confusion Matrices

[INSERT FIGURE 7.13: `docs/figures/rf_confusion_matrix.png` — Random Forest confusion matrix]

[INSERT FIGURE 7.14: `docs/figures/xgb_confusion_matrix.png` — XGBoost confusion matrix]

[INSERT FIGURE 7.15: `docs/figures/dt_confusion_matrix.png` — Decision Tree confusion matrix]

[INSERT FIGURE 7.16: `docs/figures/lr_confusion_matrix.png` — Logistic Regression confusion matrix]

### 7.5.5 Feature Importance Analysis

The following figures illustrate which of the 13 engineered features contributed most to each model's decision-making. Across all models, `frame_count`, `deauth_rate`, and `unique_targets` consistently ranked highest.

[INSERT FIGURE 7.17: `docs/figures/feature_importance_comparison.png` — Cross-model feature importance comparison]

[INSERT FIGURE 7.18: `docs/figures/rf_feature_importance.png` — Random Forest feature importance]

[INSERT FIGURE 7.19: `docs/figures/xgb_feature_importance.png` — XGBoost feature importance]

[INSERT FIGURE 7.20: `docs/figures/dt_feature_importance.png` — Decision Tree feature importance]

[INSERT FIGURE 7.21: `docs/figures/lr_coefficients.png` — Logistic Regression feature coefficients]

[INSERT FIGURE 7.22: `docs/figures/mutual_information.png` — Mutual information scores for all 13 features]

[INSERT FIGURE 7.23: `docs/figures/dt_tree_structure.png` — Decision Tree structure (first 3 levels)]

### 7.5.6 Learning Curves

Learning curves confirm that all four models converge as training data increases, with no signs of overfitting (training and validation curves converge closely).

[INSERT FIGURE 7.24: `docs/figures/rf_learning_curve.png` — Random Forest learning curve]

[INSERT FIGURE 7.25: `docs/figures/xgb_learning_curve.png` — XGBoost learning curve]

[INSERT FIGURE 7.26: `docs/figures/dt_learning_curve.png` — Decision Tree learning curve]

[INSERT FIGURE 7.27: `docs/figures/lr_learning_curve.png` — Logistic Regression learning curve]

### 7.5.7 Error Analysis

[INSERT FIGURE 7.28: `docs/figures/error_analysis_fp.png` — False positive analysis: which normal samples were misclassified]

[INSERT FIGURE 7.29: `docs/figures/error_analysis_fn.png` — False negative analysis: which attacks were missed]

### 7.5.8 ML Pipeline Summary

[INSERT FIGURE 7.30: `docs/figures/final_dashboard.png` — Complete ML pipeline result dashboard]

### 7.5.9 System Response Times

**Table 7.4: System Response Times**

| Operation | Average | Maximum | Assessment |
|---|---|---|---|
| Login | 234ms | 450ms | Excellent |
| Network registration | 156ms | 320ms | Excellent |
| Attack detection | 180ms | 450ms | Good |
| Prevention trigger | 520ms | 890ms | Good |
| Dashboard load | 1.2s | 2.1s | Acceptable |

### 7.5.10 Honeypot Effectiveness

**Table 7.5: Honeypot Effectiveness**

| Metric | Without Honeypot | With Honeypot |
|---|---|---|
| Visible APs to attacker | 1 (real) | 151 (1 real + 150 fake) |
| Attack success rate (1st try) | 100% | 0.67% |
| Average attempts needed | 1 | ~22,500 |

### 7.5.11 Comparison with Existing Systems

**Table 7.6: Comparison with Existing Systems**

| Feature | Our System | Kismet | Waidps |
|---|---|---|---|
| Detection accuracy | 98.5% | ~73% | ~80% |
| Real-time prevention | Yes (3 levels) | No | Partial |
| Honeypot | Yes (150 decoys) | No | No |
| Email + SMS alerts | Yes | No | Email only |
| Forensic PCAP + PDF | Yes | PCAP only | No |
| Web dashboard (RBAC) | Yes | Basic | CLI only |

---

## 7.6 Result Interpretation

The three-layer detection approach achieved 96.8% overall accuracy. Layer 1 alone detected 100% of high-rate attacks within 5ms. For low-rate attacks where Layer 1 scored below threshold, Layer 2 ML correctly classified all but one case across the test set. Layer 3 confirmed spoofing accurately in all controlled test cases.

The 47ms victim reconnection (Level 1 Fast Reconnection) is imperceptible to users — well below the 200ms threshold for human awareness of network interruption. The honeypot reduces the attacker's first-try success probability from 100% to 0.67%, and on average requires 22,500 attempts before the real network is consistently targeted.

> **Note:** UI screenshots of the application (Login Page, Admin Dashboard, Detection Monitor, Prevention Dashboard, etc.) are presented in **Chapter 9: Appendix**.

---

