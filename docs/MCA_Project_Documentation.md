# REAL-TIME WI-FI DEAUTHENTICATION ATTACK DETECTION AND PREVENTION SYSTEM

**A Project Report Submitted in Partial Fulfillment of the Requirements for the Award of the Degree of**

**MASTER OF COMPUTER APPLICATIONS (MCA)**

---

Department of Computer Science and Applications
[Your Institution Name]
[University Name]
[Year]

---

**Submitted by:**
[Your Name] — [Roll Number]

**Under the Guidance of:**
[Guide Name], [Designation]
Department of Computer Science

---

---

# CHAPTER 1: INTRODUCTION

## 1.1 About the Project

Wi-Fi networks are the primary communication infrastructure in colleges, hospitals, offices, and homes. With this widespread dependency, wireless networks have become attractive targets for people who want to deliberately disrupt connectivity. Among the various attacks that exploit the IEEE 802.11 standard, the **deauthentication (deauth) attack** stands out as particularly damaging because it requires no cracking of encryption — it exploits a protocol-level flaw that has existed since the beginning of the 802.11 standard.

Management frames in 802.11 — the frames that handle connection, disconnection, and authentication between a client device and an access point — carry no cryptographic authentication by default. An attacker within radio range can fabricate a deauthentication frame, stamp a spoofed source MAC address on it (pretending to be the legitimate access point), and broadcast it. Every client on the network receives this frame, treats it as genuine, and disconnects. The entire sequence takes less than 100 milliseconds. There is no user notification, no error log visible to non-technical staff, and no built-in recovery mechanism.

This project — **Real-Time Wi-Fi Deauthentication Attack Detection and Prevention System** — is an end-to-end platform that detects this class of attack the moment it begins and responds to it automatically, without requiring any human decision or command-line interaction. 

The system operates on three distinct analytical layers followed by an automated response:
- **Multi-Layered Detection Architecture:**
    - **Layer 1 (Heuristics):** Performs sub-millisecond analysis of packet frequency, sequence number continuity, and protocol reason codes to detect high-rate flood patterns characteristic of automated attack tools.
    - **Layer 2 (Machine Learning Ensemble):** Uses a weighted ensemble of four trained classifiers (Random Forest, XGBoost, Decision Tree, and Logistic Regression) to validate threats against a 13-feature vector, achieving a 96.5% detection accuracy.
    - **Layer 3 (Physical Fingerprinting):** Tracks hardware-specific clock drift (TSF timestamps) and signal strength (RSSI) profiles to distinguish legitimate access points from attackers spoofing MAC addresses.
- **Autonomous Prevention Engine:** A dynamic response system that escalates through three resilience levels (Fast Reconnection, Application Resilience, and UX Optimization), focusing on seamless connection preservation and application buffering rather than blocking MAC addresses.
- **Real-Time Monitoring Feed:** A persistent SSE-driven dashboard that visualizes packet metadata, heuristic sub-scores, and ML confidence levels in real-time.

The system is structured into six tightly integrated modules that together cover the full lifecycle from user registration through to real-time dashboard monitoring.

---

### Module 1 — User and Wi-Fi Registration

Before any packet capture or detection can happen, the system needs to know which Wi-Fi networks it is protecting and who is authorised to view or manage detection data.

The registration module is built on the Spring Boot backend using Spring Security with JWT-based authentication. Three user roles are supported:
- **Admin** — full system control: trigger scans, view all alerts, manage users and Wi-Fi networks, access the Prevention Dashboard.
- **Viewer** — read-only access to detection events for their own institution's network.
- **Home User** — a simplified view restricted to their personally registered home network.

Each user is linked to an **Institute** entity at the database level. Every Wi-Fi network registered by an Admin is stored with its SSID, BSSID (the access point's physical MAC address), location, and security type. All detection events, anomaly records, and scan results are then scoped to the institute — so a Viewer at College A cannot see alerts from College B. This multi-tenant isolation is enforced through foreign key relationships in MySQL between the `users`, `institutes`, `wifi_networks`, `detected_anomalies`, and `scan_results` tables.

When an Admin registers a Wi-Fi network, its BSSID is stored as the baseline for Layer 3 physics fingerprinting — the system will compare all observed beacon TSF timestamps against this registered AP going forward.

---

### Module 2 — Packet Capture Engine

The Packet Capture Engine is a Python module (`PacketSniffer`) built on the Scapy library. It runs on a wireless network interface that is placed into **monitor mode** — a special operating state where the adapter hears every 802.11 frame in the air, regardless of which network or device that frame belongs to.

The sniffer classifies each captured frame into one of seven types: `beacon`, `deauth`, `disassoc`, `probe_req`, `probe_resp`, `assoc_req`, or `other`. Two distinct callbacks handle the output:

- **All-frame callback** — every frame, regardless of type, goes to the `BehavioralTracker` for building per-MAC RSSI and TSF baseline profiles. Beacon and probe response frames include a TSF (Timing Synchronization Function) 64-bit microsecond counter that is specific to each access point's hardware clock; this value is extracted and stored for later comparison.

- **Deauth callback** — when a deauthentication or disassociation frame is detected, a structured packet record is assembled containing: source MAC, destination MAC, BSSID, sequence number, RSSI (extracted from the RadioTap header), reason code, frame type, and timestamp. This record is sent to the Spring Boot backend via the `/api/packets/deauth/batch` REST endpoint.

The RSSI extraction uses the RadioTap header's `dBm_AntSignal` field. If the primary parsing path fails, a secondary fallback reads the RadioTap layer directly through Scapy. The sniffer runs as a daemon thread and restarts automatically on any interface error.

---

### Module 3 — Detection Engine (Core Logic)

The Detection Engine is the technical centrepiece of the project. It receives the raw packet data from Module 2 and runs a three-layer parallel analysis to produce a final threat confidence score between 0 and 100.

**Layer 1 — Rule-Based Heuristic Analysis**

`Layer1Service` in the Spring Boot backend runs four sub-analysers simultaneously using Java `CompletableFuture` with a dedicated thread pool:

| Sub-Analyser | What It Checks | Weight |
|---|---|---|
| `RateAnalyzer` | Number of deauth frames per second from a given source MAC | 35% |
| `SequenceValidator` | Whether 802.11 sequence numbers follow a logical increment pattern | 25% |
| `TimeAnomalyDetector` | Whether the activity time matches legitimate usage hours (time-of-day model) | 15% |
| `SessionStateChecker` | Whether the deauth event follows a valid association/authentication sequence | 20% |

Each analyser returns a score out of 100. The combined Layer 1 score is the weighted average: `(rate×0.35) + (seq×0.25) + (time×0.15) + (session×0.20)`. The entire four-analyser parallel run completes within a 5 ms timeout — if any single analyser exceeds the timeout, it returns 0 gracefully and the other results are still used.

Threat levels from Layer 1 alone: score ≥ 50 → CRITICAL, ≥ 30 → HIGH, ≥ 15 → MEDIUM, below 15 → LOW.

**Layer 2 — Machine Learning Ensemble**

`Layer2Service` passes a 13-feature vector to the ML API (Flask server, `localhost:5000/predict`). The `FeatureExtractor` derives these features from the raw packet data and the Layer 1 sub-scores: frame rate, sequence number variance, mean inter-frame interval, RSSI, RSSI delta, hour of day, day of week, victim count, deauth reason code, time since last legitimate association, association session duration, estimated throughput, and Wi-Fi channel.

**Dataset and training:** The ML models were trained on a dataset of 1,00,000 labelled samples (50,000 attack-class, 50,000 normal-class), augmented from 97 real captured packets using controlled Gaussian noise to simulate real-world traffic variation. The 80/20 stratified train-test split preserved class balance in both sets.

**Challenges encountered and resolved during training:**

During model development, four significant problems were identified and systematically fixed before the models were considered production-ready:

- **Data leakage (100% accuracy):** The first training run produced 100% accuracy across all four models — a clear sign something was wrong. One feature (`reason_code`) had zero class overlap in the initial dataset, allowing every model to make a perfect split on that single feature alone without learning any real attack pattern. Controlled noise (5% Gaussian, 2% label flips, 3% class swaps) was injected to force all models to learn from the full feature set.

- **Multicollinearity (r = 0.92):** `mean_interval` and `std_interval` were 92% correlated — nearly redundant. After testing three approaches in 5-fold cross-validation, `std_interval` was dropped, reducing the feature count from 14 to 13 with only a 0.07% accuracy loss and eliminating coefficient instability in Logistic Regression.

- **Overfitting (12.6% train-test gap):** Without depth constraints, Random Forest showed a 12.6% gap (99.8% train accuracy vs 87.2% test). Decision Tree was worse at 17.5%. Hyperparameter constraints — `max_depth`, `min_samples_leaf`, `min_samples_split`, L1/L2 regularisation on XGBoost and Logistic Regression — brought all model gaps below 1.1%.

- **Identical results across models:** Random Forest and XGBoost gave fold-by-fold identical cross-validation scores — statistically impossible for two different algorithms. Uniform noise distribution had forced both onto the same decision boundary. Feature-specific noise (RSSI ±3 dBm, throughput ±15%, frame rate ±10%) and differentiated hyperparameters resolved this.

**Final model accuracy after all fixes:**

| Model | Test Accuracy | Train-Test Gap |
|---|---|---|
| Random Forest | 96.3% | 0.26% |
| XGBoost | 96.4% | 1.02% |
| Logistic Regression | 96.5% | 0.14% |
| Decision Tree | 96.2% | 0.23% |

All four models were validated with 5-fold cross-validation, confusion matrices, and ROC curves. They are deployed as `.pkl` files served by the Flask API.

**Ensemble voting:** Each model independently classifies the frame as ATTACK (1) or NORMAL (0). The final ML confidence score is the weighted vote: `(Σ prediction × weight) / total_weight × 100`, where Random Forest and XGBoost carry 0.30 weight each, and Decision Tree and Logistic Regression carry 0.20 each. A confidence above 50% is classified as ATTACK.

**Layer 3 — Physics-Based Spoofing Verification**

Layer 3 compares the TSF timestamp values extracted from beacon frames against the stored baseline for the registered BSSID. A genuine access point's clock crystal has a consistent, predictable drift rate. An attacker spoofing the AP's BSSID cannot accurately replicate this clock behaviour — the TSF values will show an anomalous jump or wrong slope. RSSI values are also compared against the per-MAC profile built by the BehavioralTracker. A device suddenly broadcasting with a known BSSID but from a different physical location will show an RSSI signature that does not match the baseline, exposing the spoofing attempt.

**Score Aggregation**

After all three layers run, the `DetectionService` takes the maximum of the Layer 1 and Layer 2 scores, then adds a partial weight from Layer 3: `final = max(L1, L2) + min(100, L3 / 2)`. This composite score is capped at 100 and saved to the `detection_events` table in MySQL. The event is then pushed to all connected SSE clients via `AlertService.broadcastAlert()`.

---

### Module 4 — Auto-Blocking Engine and Prevention

The Prevention Engine is a continuously running Python process (`PreventionEngine`, `prevention-engine/level1.py`). It subscribes to the backend's SSE stream at `/api/detection/stream` and receives every detection event in real time. Based on the final composite score and ML confidence, it escalates through three resilience levels:

| Level | Trigger Condition | Defense Actions |
|---|---|---|
| **Level 1 (Fast Reconnection)** | Score ≥ 40 | Pre-Association Caching (OKC), Aggressive Probe Response, Channel Hint Broadcasting, and Predictive Pre-Authentication via `wpa_cli`. |
| **Level 2 (Application Resilience)** | Score ≥ 60 | TCP Connection Preservation, Multipath TCP (MPTCP) activation, Smart Buffering (up to 134MB), and Intelligent Download Manager configuration (`aria2`/`wget`). |
| **Level 3 (UX Optimization)** | Score ≥ 85 | Perceptual Masking of OS disconnected notifications, Notification Suppression (delaying NetworkManager alerts), Seamless Handoff Illusion, and Progressive Degradation of streaming quality. |

The engine is designed around a critical constraint identified in IEEE 802.11 security research: **MAC address blocking punishes victims, not attackers**. In a deauth attack, the source MAC address is spoofed — it belongs to the victim or the AP, not the attacker. Blocking by MAC would disconnect the legitimate device. The prevention engine therefore never adds a MAC to a firewall blocklist; instead, it proactively masks the attack's effects from the user and retains the network session at the packet level.

A **Kill Chain State Machine** maintains a persistent accumulated threat score per attacker identity across multiple events. Scores decay slowly over time.

Additionally, the system provisions standalone **Honeypot** and **Forensics** modules to deceive attackers through BSSID cloning and to capture evidence for later analysis.

---

### Module 5 — Alert and Notification System

Every detection event, regardless of severity, is processed by `AlertService` in the Spring Boot backend. The service maintains an in-memory list of up to 500 recent alerts using `CopyOnWriteArrayList`. Each alert is immediately broadcast to all active SSE connections (`SseEmitter` instances) so that every open dashboard page receives the update in real time without polling.

Alert types used by the system:
- `MONITOR_ALERT` — LOW or MEDIUM severity events
- `CRITICAL_ALERT` — HIGH or CRITICAL severity events
- `BLOCK_ALERT` — sent when the Prevention Engine takes a defense action
- `DEAUTH_PACKET` — raw packet events streamed directly to the Detection Monitor feed

For CRITICAL and HIGH alerts, the `NotificationService` in the Prevention Engine triggers an email/SMS alert structure. *(Note: While the alert orchestration is fully designed and implemented in the backend logic, the final dispatch to the Brevo transactional mail API is designated as a future planned feature that can be enabled by supplying the requisite production API keys.)*

When fully enabled, the email alerting system will throttle notifications using a per-attacker MAC cooldown of 10 minutes and a daily cap of 50 emails to prevent spamming during sustained attacks. The email will contain the attacker MAC, victim MAC, BSSID, threat score, detection method, and a timestamp, giving the administrator enough information to act without referring to the dashboard.

---

### Module 6 — Web Dashboard

The frontend is a React (TypeScript) single-page application built with Vite. It connects to the Spring Boot backend via JWT-authenticated REST API calls and a persistent `EventSource` SSE connection. The dashboard is divided into role-specific views:

**Admin Dashboard:**
- System status tile (Safe / Under Attack), based on whether any CRITICAL/HIGH event has occurred in the last 15 seconds
- Attacks detected in the last hour counter
- Heuristic score breakdown (Rate analyser, Sequence validator, Time anomaly, Session state)
- Manual Wi-Fi scan trigger → calls `/api/scan/trigger`
- List of registered Wi-Fi networks and connected clients

**Detection Monitor:**
- Live Detection Feed — streams every `CRITICAL_ALERT` and `MONITOR_ALERT` event in real time via SSE
- Recent Deauth Packets table — lists raw deauth frames with source MAC, destination MAC, BSSID, reason code, RSSI, Layer 1 score, Layer 2 ML confidence, and Layer 3 spoofing flag
- System Status indicator updates live as the stream receives new events

**Prevention Dashboard:**
- Blocked MAC list with block level and expiry time
- Prevention event history (BLOCK_ALERT, CRITICAL_ALERT, MAX_PREVENTION events)
- Read-only system configuration settings

**Viewer Dashboard:**
- Simplified read-only view of the Detection Feed and packet list for the Viewer's institution

**Home Dashboard:**
- Condensed status view for Home Users showing only their registered home network

All typography and UI components use a consistent visual language: `font-mono`, uppercase labels, `tracking-[0.2em]`, and `text-[11px]` — matched across all pages for a uniform, professional appearance. The SSE connection auto-reconnects within 5 seconds of any disconnection.

---

## 1.2 Objectives of the Project

The following concrete objectives guided the development of this system:

1. **Capture live 802.11 management frames** from a wireless interface running in monitor mode, including all deauthentication, disassociation, beacon, and probe frames.

2. **Detect deauthentication attacks in real time** using a three-layer analysis pipeline: rule-based heuristics at Layer 1, a four-model ML ensemble at Layer 2, and TSF/RSSI physical fingerprinting at Layer 3.

3. **Confirm MAC address spoofing** through physics-based fingerprinting so that the system can separate genuine administrative disconnects from injected attack traffic.

4. **Respond automatically at three resilience levels** using connection persistence (OKC pre-authentication), TCP flow preservation, application buffering, and OS-level notification masking — ensuring the user experience remains uninterrupted even during an active attack.

5. **Maintain a persistent Kill Chain State Machine** that accumulates threat scores over time, so an attacker launching slow, low-rate attacks cannot evade detection by staying just under per-event thresholds.

6. **Reconnect victim devices** within 200–300 milliseconds of detecting a confirmed attack, using `wpa_cli reassociate` as the primary fast path.

7. **Provide a real-time web dashboard** with role-based access (Admin, Viewer, Home User), live SSE event streaming, and a visual representation of threat scores, detection events, and prevention actions.

8. **Send throttled email alerts** to administrators on high-confidence detections, with per-attacker MAC cooldown and daily volume limits to stay within email API rate limits.

---

## 1.3 Scope of the Project

This project is scoped for deployment in **institutional and home Wi-Fi environments**. Its primary use case is a college or office campus where a network security administrator needs an automated, real-time response to deauthentication attacks without having to monitor traffic manually.

**In scope:**
- IEEE 802.11 deauthentication and disassociation frame detection
- Multi-layer ML and heuristic attack analysis
- Automated application resilience at three configurable prevention levels
- Real-time web dashboard with SSE streaming
- Role-based user management (Admin, Viewer, Home User)
- Email alerting via Brevo API with throttling
- Forensic packet capture and report generation
- Kill Chain State Machine for persistent attacker tracking

**Out of scope:**
- WPA2/WPA3 key cracking or cryptographic attacks
- Attacks against wired (Ethernet) infrastructure
- Detection of attacks on networks other than the monitored interface
- Legal response or law enforcement coordination (covered as a policy recommendation only)

---

## 1.4 Technology Stack

| Component | Technology |
|---|---|
| Packet Capture | Python, Scapy |
| Machine Learning API | Python, Flask, scikit-learn, XGBoost |
| Backend API | Java 17, Spring Boot 3, Spring Security (JWT), Spring Data JPA |
| Database | MySQL |
| Frontend | React (TypeScript), Vite, Tailwind CSS |
| Real-Time Events | Server-Sent Events (SSE) |
| Email Alerts | Brevo Transactional Mail API |
| Network Defense | sysctl, hostapd, wpa_cli, nmcli |
| Kernel-Level Configuration | sysctl network buffers, tcp preservation |
| Version Control | Git |
| OS Environment | Ubuntu Linux (kernel 6.x) |

---

## 1.5 Organisation of the Report

The remaining chapters of this report are organised as follows:

- **Chapter 2: System Analysis** — covers the existing system study, problem statement, feasibility analysis, and the results of requirements gathering (functional and non-functional).
- **Chapter 3: System Design** — covers the architecture of the system including the data flow diagram, UML diagrams (use case, class, sequence), database schema, and component design.
- **Chapter 4: Implementation** — covers the actual code, module descriptions, and a walkthrough of key implementation decisions.
- **Chapter 5: Testing** — covers the testing methodology, test cases, and results including simulation of real deauth attacks.
- **Chapter 6: Conclusion and Future Work** — summarises what was achieved and identifies areas for future enhancement.

---

---

# CHAPTER 2: SYSTEM ANALYSIS

## 2.1 Study of the Existing System

### 2.1.1 How Deauthentication Attacks Are Currently Handled

At the time of designing this project, the standard approach for dealing with deauthentication attacks in most academic and small business environments fell into one of three categories:

**1. No detection at all.** The majority of institutions running a standard Wi-Fi router or a basic enterprise access point have no mechanism to detect deauth attacks. The administrator notices slow connectivity or user complaints, reboots the router, and assumes it was a transient issue. The attack goes undetected entirely.

**2. Manual packet capture and analysis.** Security-conscious administrators use tools like Wireshark or `tcpdump` to capture traffic and manually look for suspicious patterns. This is reactive — the attack has already disconnected all users by the time the administrator opens Wireshark. It is also not viable during an ongoing attack because it requires continuous manual attention.

**3. Intrusion Detection System (IDS) tools.** Tools like Kismet and Waidps can flag deauth attacks. However, these tools:
- Run only as detection systems — they do not take any prevention action.
- Generate alerts through log files that must be checked periodically.
- Have no web-based dashboard for non-technical stakeholders.
- Cannot differentiate accurately between genuine AP-initiated disconnects and spoofed deauth floods, causing high false positive rates.
- Do not integrate with a backend API for storing and querying historical attack data.

### 2.1.2 Limitations of the Existing System

| Problem | Impact |
|---|---|
| **Passive Monitoring Limitation** | Existing monitoring is purely passive, requiring manual data collection and analysis using tools like Wireshark. |
| **Lack of Centralized Resilience Management** | There is no centralized dashboard or system to manage alerts or orchestrate automated connection resilience strategies across multiple interfaces. |
| **Delayed Attack Awareness** | Administrators only become aware of an attack after users report connectivity loss; there is no predictive or immediate notification. |
| **No Real-Time Detection** | Deauthentication attacks are mostly not detected in real time, leading to significant disruption before recovery is attempted. (Alaa Btoush, 2024) |
| **Slow Detection Mechanism** | Most existing research prototypes and open-source tools use batch processing, which detects attacks too slowly to prevent the initial disconnect. |
| **Single-Layer Detection** | Most systems rely on a single detection layer (e.g., only rate-limiting), which is easily bypassed by "low and slow" attacks. (Aminanto, 2018) |
| **Low Detection Accuracy** | Relying on a single layer leads to high false positive rates (flagging real users) or poor accuracy in distinguishing spoofed traffic. |
| **Manual Attack Mitigation** | Current mitigation requires an administrator to manually identify the attacker and apply firewall rules, which is impossible during rapid deauth floods and actively harms the victim if the attacker is spoofing their MAC. |
| **No MAC Spoofing Confirmation** | Failing to use Layer 3 physics fingerprinting means systems cannot distinguish real AP management traffic from spoofed frames. |
| **No Persistent Tracking** | Attackers can evade threshold-based detectors by spreading their activity over time, as most current tools have no behavior "memory." |

### 2.1.3 Tools Being Replaced or Addressed

The following existing open-source tools were studied as part of the background research:

**Kismet:** A wireless network detector, sniffer, and IDS. Kismet can identify deauth packets but takes no automatic prevention action and relies on log review. It also has a complex setup that is not appropriate for non-technical users.

**Waidps (Wireless Auditing, Intrusion Detection & Prevention System):** Closer to this project's goal, Waidps attempts to detect and prevent wireless attacks. However, it has not been actively maintained since 2014, does not support modern Python 3 cleanly, has no web-based interface, and uses MAC blocking as its primary prevention approach — which inadvertently punishes victims rather than maintaining their connection.

**aireplay-ng / aircrack-ng:** Using these tools offensively to "counter-attack" the attacker is not legal in most jurisdictions without explicit written permission. This project takes a strictly defensive, non-offensive approach.

---

### 2.1.4 Problem Statement

Wi-Fi deauthentication attacks exploit the absence of cryptographic authentication in IEEE 802.11 management frames. Any device within radio range can inject a forged deauthentication frame bearing a spoofed AP BSSID, causing every client on the network to disconnect simultaneously. The window between the first injected frame and client disconnection is under 100 milliseconds — far below any human reaction time.

Existing systems either detect without preventing, prevent through ineffective means like blocking victim MAC addresses, or require manual intervention. There is no open, self-contained system that:
- Captures frames at the kernel level in real time
- Applies ML-based classification to distinguish genuine disconnects from attacks
- Confirms spoofing through physics-based fingerprinting (TSF clock skew, RSSI profiling)
- Responds automatically within the same 100 ms window
- Maintains persistent threat history across multiple attack sessions
- Provides a structured, role-based web dashboard for monitoring and management

This is the gap this project fills.

---

## 2.2 Proposed System

The proposed system is an integrated, full-stack security platform designed to detect, verify, and autonomously mitigate deauthentication attacks. Unlike existing passive monitoring tools, this system implements a proactive **3-Level Resilience Strategy** that focuses on maintaining application connectivity and user experience even while an attack is underway.

The primary highlights of the proposed system include:

**1. Multi-Layer Real-Time Detection:**
The system captures raw 802.11 frames using monitor mode and applies a three-layer detection pipeline:
- **Layer 1 (Heuristics):** Rapid analysis of frame rates and sequence gaps.
- **Layer 2 (ML Ensemble):** Voting-based classification using Random Forest, XGBoost, Decision Tree, and Logistic Regression with a 96.5% accuracy rate.
- **Layer 3 (Physics Fingerprinting):** Verification of TSF clock drift and RSSI signal profiles to distinguish legitimate APs from software-based spoofers.

**2. Autonomous 3-Level Resilience:**
The system automatically escalates through three resilience levels based on the calculated threat score:
- **Level 1 (Fast Reconnection):** Uses Opportunistic Key Caching (OKC) and predictive pre-authentication to reduce reconnect time to <200ms.
- **Level 2 (Application Resilience):** Adjusts kernel `sysctl` parameters to preserve TCP flows, increases network buffers to 134MB, and enables Multipath TCP (MPTCP) for session persistence.
- **Level 3 (UX Optimization):** Suppresses OS disconnected notifications and implements progressive degradation for streaming services to keep the attack invisible to the end-user.

**3. Zero-MAC-Blocking Philosophy:**
The system identifies that MAC addresses in deauthentication attacks are spoofed. Instead of blocking the victim's MAC (which traditional systems often do), it restricts the impact of the attack through buffer expansion and rapid re-association, keeping the victim connected.

**4. Distributed Node Architecture:**
The architecture separates high-speed packet sniffing (Python/Scapy) from heavy analytical processing (Java/Spring Boot), ensuring that the capture engine remains responsive even during high-rate flood attacks.

### 2.2.1 Advantages of the Proposed System

| Advantage | Description |
|---|---|
| **Zero Disruptivity** | Users remain connected during attacks due to proactive TCP preservation and massive kernel-level buffering. |
| **High Accuracy** | The ensemble ML approach combined with Physics-based fingerprinting (TSF/RSSI) virtually eliminates false positives from genuine network congestion. |
| **Invisible Protection** | By masking OS deauthentication alerts and notifications, the system ensures that the end-user is never bothered by technical security events. |
| **Predictive Recovery** | The system initiates `wpa_cli reassociate` sequences *before* the OS network manager realizes the connection is lost, leading to near-zero downtime. |
| **Centralized Governance** | A single dashboard allows administrators to monitor multiple network segments, view historical attack data, and manage role-based access for different stakeholders. |
| **Forensic Readiness** | The system automatically captures and logs attack metadata, providing a detailed audit trail including attacker RSSI profiles and sequence number anomalies. |

---

## 2.3 Feasibility Study

Before development began, a feasibility study was conducted across three dimensions.

### 2.3.1 Technical Feasibility

**Packet capture:** The Scapy library in Python provides full access to raw 802.11 frames when the network interface is placed in monitor mode. RadioTap headers, which carry RSSI and timing information, are accessible directly. This was verified during early testing on a TP-Link TL-WN722N adapter running on Ubuntu 22.04.

**Machine learning:** The scikit-learn library provides Decision Tree, Random Forest, and Logistic Regression classifiers. XGBoost is available as a standalone package. Training was performed on a dataset combining the publicly available AWID (Aegean Wi-Fi Intrusion Dataset) and locally captured traffic. A 13-feature vector covering packet rate, sequence gap, reason code, RSSI variance, TSF delta, and similar metrics was found to be sufficient for reliable classification.

**Backend API:** Spring Boot 3 with Spring Security and JWT authentication is a well-documented, production-grade choice for REST API development. Spring's built-in support for SSE (`SseEmitter`) allows event streaming to frontend clients without a separate WebSocket server.

**Frontend:** React with TypeScript and Vite was selected for its component model, which makes real-time UI updates straightforward using `useState` and `useEffect` hooks connected to an SSE event source.

**Defense mechanisms:** `sysctl` is available on all Linux systems for configuring TCP preservation and buffers. `hostapd` supports BSSID-cloning for honeypot creation. `wpa_supplicant` exposes `wpa_cli reassociate` for sub-200ms reconnection. These tools were tested in a controlled lab environment and confirmed to work as expected.

**Conclusion:** Technically feasible using existing, well-maintained open-source tools.

### 2.3.2 Operational Feasibility

The system is designed to run as a background service on a Linux machine with a compatible wireless adapter. Once deployed, it requires no manual intervention during operation. The web dashboard allows non-technical users (college network administrators, HODs) to monitor the system and acknowledge alerts without touching the command line.

The role-based access model (Admin, Viewer, Home User) ensures that full system control is restricted to authorised personnel, while read-only monitoring is available more broadly.

Email alerting with per-attacker cooldown and daily limits means administrators are not flooded with notifications during a sustained attack.

**Conclusion:** Operationally feasible for institutional deployment.

### 2.3.3 Economic Feasibility

All software components used in this project are free and open source. The only third-party service cost is the Brevo email API, which has a free tier of 300 emails per day — more than sufficient for alert volume with throttling in place.

The hardware requirement is a Linux machine (a Raspberry Pi 4 or any low-cost PC is sufficient) and a monitor-mode-capable USB WiFi adapter (approximately ₹800–₹1,500 in the Indian market).

There is no proprietary licence, cloud subscription, or ongoing software cost.

**Conclusion:** Economically feasible with minimal cost.

---

## 2.4 Requirements Analysis

### 2.4.1 Functional Requirements

**FR-01: Packet Capture**
The system shall capture IEEE 802.11 frames from a wireless network interface operating in monitor mode. It shall classify frames as beacon, deauth, disassociation, probe request, probe response, association request, or other management/control/data frames.

**FR-02: Layer 1 Heuristic Detection**
The system shall evaluate deauthentication packet frequency, sequence number gaps, broadcast vs unicast targeting, and deauth reason codes to compute a rule-based threat score for each observed source MAC address.

**FR-03: Layer 2 ML-Based Classification**
The system shall extract a 13-feature vector from captured packet streams and pass it to an ensemble of four pre-trained classifiers (Decision Tree, Random Forest, Logistic Regression, XGBoost). The system shall compute a weighted confidence score between 0 and 100 representing the probability that detected traffic constitutes an attack.

**FR-04: Layer 3 Physics-Based Spoofing Detection**
The system shall track TSF timestamps from beacon and probe response frames for each observed BSSID. It shall detect clock skew anomalies that indicate a device is broadcasting with a spoofed BSSID. The system shall also maintain per-MAC RSSI profiles and flag anomalous signal strength patterns.

**FR-05: Automated Defense Response**
The system shall respond automatically to confirmed attacks at three escalating resilience levels:
- Level 1 (threat score ≥ 40): Fast Reconnection (OKC, predictive pre-authentication)
- Level 2 (score ≥ 60): Application Resilience (TCP preservation, smart buffering)
- Level 3 (score ≥ 85): UX Optimization (Notification suppression, streaming quality degradation)

**FR-06: Victim Reconnection**
On detection of an active attack against a specific client, the system shall attempt reconnection via `wpa_cli reassociate` within 200–300 ms.

**FR-07: Kill Chain State Machine**
The system shall maintain a persistent threat score per attacker MAC across multiple attack events. Scores shall decay slowly over time, so that an attacker using a slow-rate strategy cannot reset to zero between individual events.

**FR-08: REST API**
The backend shall expose REST endpoints for:
- Login and JWT token issuance
- Trigger manual Wi-Fi network scan
- Retrieve latest scan results and detected anomalies
- Query historical deauth packets and detection events
- Query honeypot and forensics status
- Retrieve prevention event history
- Stream real-time detection events via SSE

**FR-09: Web Dashboard**
The frontend shall provide:
- Landing page with role-based login
- Admin Dashboard with attack statistics and scan control
- Detection Monitor with live detection feed and recent packet list
- Prevention Dashboard with blocked MAC list and prevention event feed
- Viewer Dashboard (read-only subset)
- Home User Dashboard (simplified view)

**FR-10: Email Alerts**
The system shall support structuring email alerts (planned integration with Brevo) when attack confidence crosses the CRITICAL threshold, with a per-attacker MAC cooldown of 10 minutes and a daily limit of 50 emails.

**FR-11: User and Institution Management**
The backend shall support multiple institutions, each with their own Admin, Viewer, and Home User accounts. Data isolation shall be enforced at the database level via institution FK relationships.

### 2.4.2 Non-Functional Requirements

**NFR-01: Response Latency**
The end-to-end time from packet capture to prevention action dispatch shall not exceed 500 ms for Layer 1 and Layer 2 analysis. Victim reconnection via `wpa_cli` shall complete within 300 ms.

**NFR-02: Detection Accuracy**
The ML ensemble shall achieve a precision of at least 90% and recall of at least 85% on the validation dataset, keeping false positives at an acceptable rate for operational deployment.

**NFR-03: Scalability**
The Spring Boot backend and MySQL database shall support concurrent connections from up to 50 registered users across multiple institutions without degradation.

**NFR-04: Security**
All API endpoints (except `/api/auth/*`) shall require a valid JWT token. Token expiry shall be set to 24 hours. Passwords shall be stored using BCrypt hashing. Cross-Origin Resource Sharing (CORS) shall be restricted to the configured frontend origin.

**NFR-05: Reliability**
The Prevention Engine listener shall automatically reconnect to the SSE stream within 5 seconds of a disconnection. The packet sniffer shall run as a daemon thread and restart automatically on error.

**NFR-06: Maintainability**
The system shall follow a modular architecture. Each component (packet sniffer, ML API, prevention engine, Spring Boot backend, React frontend) shall function independently and communicate only through well-defined REST or SSE interfaces.

**NFR-07: Usability**
The web dashboard shall be operable without command-line access. Common administration tasks (viewing alerts, checking blocked devices, triggering scans) shall be completable in fewer than three clicks.

**NFR-08: Portability**
The Python components (packet sniffer, prevention engine, ML API) shall run on any Linux system with a kernel version 5.x or above and a monitor-mode-capable wireless adapter, without modification.

---

## 2.5 Hardware and Software Requirements

### 2.5.1 Hardware Requirements

| Component | Minimum Specification |
|---|---|
| Processor | Dual-core 1.5 GHz (ARM or x86) |
| RAM | 4 GB DDR4 |
| Storage | 20 GB free disk space |
| Wireless Adapter | Monitor-mode–capable USB adapter (e.g., TP-Link TL-WN722N with Atheros AR9271 chipset) |
| Network | Wired Ethernet for backend server connectivity |

### 2.5.2 Software Requirements

| Software | Version | Purpose |
|---|---|---|
| Ubuntu Linux | 22.04 LTS | Operating system |
| Python | 3.11+ | Packet sniffer, ML API, Prevention Engine |
| Scapy | 2.5+ | Raw packet capture and parsing |
| scikit-learn | 1.4+ | ML model training and inference |
| XGBoost | 2.0+ | Gradient boosting classifier |
| Flask | 3.0+ | ML API web server |
| Java | 17 LTS | Spring Boot backend runtime |
| Spring Boot | 3.2+ | REST API framework |
| MySQL | 8.0+ | Relational database |
| Node.js | 20+ | Frontend build toolchain |
| React | 18+ | Frontend framework |
| TypeScript | 5+ | Frontend language |
| Vite | 5+ | Frontend build tool |
| sysctl | Linux | TCP and Buffer Configuration |
| hostapd | 2.10+ | Honeypot AP creation |
| wpa_supplicant | 2.10+ | Fast victim reconnection |

---

## 2.6 Data Flow Overview

At a high level, data moves through the system in the following sequence:

    1. The **PacketSniffer** module captures raw frames from the wireless interface. Each frame is parsed using Scapy to extract source MAC, destination MAC, BSSID, RSSI (from RadioTap), TSF timestamp (from beacon/probe frames), reason code, sequence number, and frame type.

    2. Deauthentication and disassociation frames are routed to the **Layer 1 analyser** in the Spring Boot backend via the `/api/packets/deauth/batch` endpoint. All other frame types go to the **BehavioralTracker** for RSSI and TSF profiling.

    3. The Spring Boot backend's `PacketProcessor` feeds the packet data to:
    - The **Layer 1 service** (rule-based scoring)
    - The **ML API** at `localhost:5000/predict` (Layer 2 classification)
    - The **Layer 3 analyser** (physics-based spoofing check using stored RSSI/TSF baselines)

    4. A composite `DetectionEvent` is constructed with the scores from all three layers, persisted to MySQL, and pushed to all **SSE clients** (dashboards) via the `DetectionController`.

    5. The **Prevention Engine** (Python), subscribing to the same SSE stream, receives each detection event and decides which defense level to activate.

    6. Defense actions are executed locally (`sysctl`, `wpa_cli`, `nmcli`) and then logged to the local database and reported back to the backend for dashboard display.

    7. If the threat confidence is CRITICAL, the **NotificationService** sends a throttled email alert via Brevo.

# CHAPTER 3: SYSTEM SPECIFICATION

## 3.1 Overview
The system specification outlines the technical environment required to develop, deploy, and operate the Wi-Fi deauthentication detection and prevention platform. The project is designed as a distributed, multi-module system where high-performance packet processing happens at the edge (Python/Scapy), analytical logic is handled by a robust backend (Java/Spring Boot), and the management interface is served via a modern web framework (React).

---

## 3.2 Hardware Requirements

The hardware must support real-time packet capture, machine learning inference, and concurrent user management.

| Component | Minimum Specification | Recommended Specification |
|---|---|---|
| **Processor** | Dual-core 1.5 GHz (ARM/x86) | Quad-core 2.4 GHz+ |
| **RAM** | 4 GB DDR4 | 8 GB DDR4+ |
| **Storage** | 20 GB free space | 128 GB SSD |
| **Wireless Adapter** | TP-Link TL-WN722N (v1) | Alfa AWUS036ACM / AWUS036NHA |
| **Monitor Mode** | Required | Required (Must support packet injection) |
| **Network** | Ethernet for server connectivity | Gigabit Ethernet |

---

## 3.3 Software Requirements

The system is built on an open-source Linux stack to ensure kernel-level access and maximum performance.

### 3.3.1 Operating System & Environment
- **OS:** Ubuntu Linux 22.04 LTS or 24.04 LTS
- **Kernel:** Linux Kernel 5.15+ (Required for eBPF/XDP and advanced RadioTap support)
- **Architecture:** 64-bit (x64) or ARM64 (Raspberry Pi 4/5)

### 3.3.2 Development & Runtime Languages
- **Python 3.11+**: Used for the Packet Sniffer, Prevention Engine, and ML Flask API.
- **Java 17 LTS**: Used for the core Spring Boot backend and business logic.
- **TypeScript & React 18**: Used for the frontend dashboard.
- **SQL (MySQL 8.0)**: Used for persistent storage of users, networks, and detection events.

### 3.3.3 Core Libraries & Frameworks
| Category | Tool / Library | Purpose |
|---|---|---|
| **Packet Processing** | Scapy 2.5.0 | Raw IEEE 802.11 frame parsing and injection |
| **Backend API** | Spring Boot 3.2.x | REST API, SSE streaming, and JWT security |
| **Machine Learning** | scikit-learn, XGBoost | Threat classification and ensemble voting |
| **Database ORM** | Spring Data JPA | Relational data management |
| **UI Styling** | Tailwind CSS | Utility-first styling for the dashboard |
| **Email API** | Brevo (formerly Sendinblue) | Transactional alert notifications |

### 3.3.4 Networking Utilities (Defense Layer)
- **sysctl:** Used for expanding network buffers and enabling MPTCP.
- **hostapd:** Used for spawning defensive honeypots and clone APs.
- **nmcli / wpa_cli:** Used for network scanning and predictive pre-authentication recovery.

---

## 3.4 System Component Architecture

The project specification is divided into four primary technical components:

1. **Edge Node (Monitor Mode):** A dedicated Python service using Scapy to sniff management frames. It requires `root/sudo` privileges to set the interface into monitor mode.
2. **Analysis Microservice:** A Flask-based API that hosts the pre-trained ML models (`.pkl` files). It performs 13-feature vector inference in under 10ms.
3. **Control Plane (Backend):** The Java Spring Boot application that orchestrates data flow, manages institution scoping, and provides the real-time SSE stream.
4. **Presentation Layer (Frontend):** A Vite-powered React application using Tailwind CSS for a premium, dark-mode responsive dashboard.

---

## 3.5 Conclusion
The specification reflects a "hybrid architecture" approach—leveraging Python's strength in network programming and ML, and Java's strength in secure, scalable enterprise API management. All software components selected are free to use and industry-standard.

---

---

---

# CHAPTER 4: SYSTEM DESIGN

## 4.1 Data Flow Diagram (High-Level)

# CHAPTER 5: MACHINE LEARNING MODEL DEVELOPMENT

## 5.1 ML Sub-Module Overview

The machine learning component of this project is responsible for Layer 2 classification — determining, with a confidence score, whether a captured burst of deauthentication frames is a genuine network management event or a deliberate attack. This component was developed in three sequential sub-modules:

| Sub-Module | Name | Purpose |
|---|---|---|
| ML-1 | Dataset Preparation | Capture real PCAP files → extract 14 features from 97 real samples → augment to 1,00,000 samples using Gaussian noise (50,000 Attack / 50,000 Normal) |
| ML-2 | Data Preprocessing and Analysis | Fix multicollinearity, drop leakage-inducing feature configurations, inject realistic noise, visualise distributions, generate correlation heatmaps, compute feature importances |
| ML-3 | Model Training and Evaluation | Train four classifiers (Decision Tree, Random Forest, Logistic Regression, XGBoost) with 5-fold cross-validation → confusion matrix, ROC curve → export `.pkl` files for Flask API serving |

---

## 5.2 ML-1: Dataset Preparation

Real-world labelled deauthentication attack datasets large enough for reliable ML training are scarce. The AWID (Aegean Wi-Fi Intrusion Dataset) provides some labelled 802.11 captures, but the available samples covering deauth-specific attacks numbered in the hundreds after filtering. To build a training set of sufficient scale, the following approach was taken:

**Step 1 — Real packet capture:** 97 real packet samples were captured using a TP-Link TL-WN722N adapter in monitor mode. Attack samples were collected by running `aireplay-ng --deauth` against a controlled test network. Normal samples were collected from legitimate disconnect events triggered by rebooting the access point and by controlled client disconnections.

**Step 2 — Feature extraction:** Fourteen features were extracted per packet sample:

| Feature Index | Feature Name | Description |
|---|---|---|
| 0 | `frame_rate` | Number of frames per second from the source MAC |
| 1 | `seq_variance` | Variance in 802.11 sequence number increments |
| 2 | `mean_interval` | Mean time between consecutive frames (seconds) |
| 3 | `std_interval` | Standard deviation of inter-frame intervals |
| 4 | `rssi` | Received signal strength (dBm) |
| 5 | `rssi_delta` | Change in RSSI from previous frame |
| 6 | `hour` | Hour of day (0–23) at capture time |
| 7 | `day_of_week` | Day of week (0 = Monday, 6 = Sunday) |
| 8 | `victim_count` | Number of distinct destination MACs targeted |
| 9 | `reason_code` | Deauthentication reason code (802.11 standard field) |
| 10 | `time_since_legit` | Seconds elapsed since last legitimate association event |
| 11 | `assoc_duration` | Duration of the preceding association session (seconds) |
| 12 | `throughput` | Estimated throughput = `frame_rate × 24` bytes |
| 13 | `channel` | Wi-Fi channel number of the captured frame |

**Step 3 — Augmentation:** From the 97 real samples, 1,00,000 samples were generated by applying controlled Gaussian noise to each real sample's feature values. The final dataset was balanced: 50,000 attack-class samples and 50,000 normal-class samples. The train-test split was 80% / 20% with stratification to preserve class balance in both sets.

---

## 5.3 ML-2: Data Preprocessing and Analysis

Before training, the dataset was subjected to a systematic preprocessing pipeline to identify and resolve data quality issues. Six distinct issues were found and addressed.

---

## 5.4 Issues Encountered During ML Model Training

### Issue 1 — Perfect Accuracy (100%): Data Leakage

**What happened:**

The first training run produced the following results across all four models:

| Model | Accuracy |
|---|---|
| Random Forest | 100% |
| XGBoost | 100% |
| Logistic Regression | 100% |
| Decision Tree | 100% |

100% accuracy on a real-world classification problem is not a result — it is a warning sign. Real Wi-Fi traffic does not separate perfectly into two classes. Some attack-level frame rates occur naturally during congested normal usage; some genuine administrative disconnects use the same reason codes as attacks.

**Root cause — identified:**

Correlation analysis showed that `reason_code` had zero class overlap in the initial dataset:
- Normal traffic samples → reason codes: 3, 4
- Attack traffic samples → reason codes: 7, 9, 15

Every model learned a single if-else rule: *"if reason_code > 5 → Attack, else Normal."* The remaining 12 features contributed nothing. This is the textbook definition of **data leakage** — one feature alone perfectly separated the classes, so the model never learned the actual attack pattern.

**Fix applied:**

Four types of controlled noise were added to the dataset:
- 5% Gaussian noise added to all continuous feature values
- 2% random label flips to simulate annotation errors
- 3% random feature value swaps between attack and normal classes
- Feature-specific noise: RSSI ±3 dBm, throughput ×U(0.85, 1.15), seq_variance +N(0, 10)

After applying noise, the models were retrained. Accuracy dropped to a realistic **96.4%** — confirming that all four models now learned genuine cross-feature patterns rather than a single decision rule.

**Faculty analogy:** Imagine an exam where Question 1's answer is always 'A' for students who pass and always 'B' for students who fail. Every student scores 100% by checking only Question 1. They learned nothing. Our dataset had the same flaw — one feature alone gave away the answer. Adding noise forced the models to study all 13 questions (features) together.

---

### Issue 2 — Multicollinearity: Redundant Features

**What happened:**

A Pearson correlation matrix was computed for all 14 features. The pair `mean_interval` and `std_interval` showed a correlation coefficient of **r = 0.92**, well above the standard multicollinearity threshold of 0.9.

These two features were carrying nearly identical information. `mean_interval` is the average time between frames; `std_interval` is the spread around that average. In a deauth flood, both drop simultaneously and proportionally — making them almost interchangeable from the model's perspective.

**Why this is a problem:**

- For **Logistic Regression**: when two features are highly correlated, the coefficient estimation becomes numerically unstable. A small change in the training data causes coefficients to swing wildly, making the model unreliable.
- For **Random Forest and XGBoost**: feature importance scores get artificially split between the two correlated features. Each receives half the importance score instead of one receiving the full weight — giving a misleading picture of which features actually drive the decision.

**Fix applied — experimentally validated:**

Three approaches were tested using 5-fold cross-validation:

| Approach | Feature Count | CV Accuracy |
|---|---|---|
| A: Keep both features | 14 | 96.45% |
| B: Drop `std_interval` | 13 | 96.38% |
| C: Replace both with their ratio | 13 | 96.42% |

Approach B was selected. The accuracy loss was only **0.07%**, which is within statistical noise for a 5-fold CV experiment. The benefit — elimination of multicollinearity with a simpler, more interpretable 13-feature model — justified the negligible performance trade-off. This is an application of Occam's Razor: the simpler model that performs equally well is preferred.

**Faculty analogy:** Carrying two identical umbrellas gives no extra protection — it just adds weight. We proved scientifically that discarding one umbrella lost only 0.07% coverage. We chose the lighter bag.

---

### Issue 3 — Overfitting: Models Memorising, Not Learning

**What happened:**

Before any hyperparameter constraints were applied, training accuracy and test accuracy diverged significantly:

| Model | Train Accuracy | Test Accuracy | Gap |
|---|---|---|---|
| Random Forest | 99.8% | 87.2% | **12.6%** |
| Decision Tree | 100% | 82.5% | **17.5%** |

A gap above 3–5% between training and test accuracy is the diagnostic threshold for overfitting. At 12.6% and 17.5%, both models were clearly memorising training samples rather than learning generalisable patterns.

**Root causes identified:**

1. **Unlimited tree depth** — trees grew until each leaf contained a single training sample. The model essentially memorised every data point individually.
2. **No minimum sample threshold per decision node** — a split was allowed even when only 1–2 samples existed in a branch, which learns noise rather than signal.
3. **No regularisation in XGBoost** — the gradient boosting model was allowed to grow arbitrarily complex, fitting every residual including noise in the training set.

**Hyperparameter constraints applied:**

*Random Forest:*
```
max_depth         = 15     (was: unlimited)
min_samples_split = 20     (was: 2)
min_samples_leaf  = 10     (was: 1)
max_features      = 'sqrt' (was: all features)
```

*XGBoost:*
```
max_depth         = 8    (was: unlimited)
learning_rate     = 0.05 (slow, conservative learning)
subsample         = 0.7  (70% of samples per tree)
colsample_bytree  = 0.7  (70% of features per tree)
gamma             = 0.5  (minimum loss reduction to split)
reg_alpha         = 0.05 (L1 regularisation)
reg_lambda        = 1.5  (L2 regularisation)
```

*Decision Tree:*
```
max_depth         = 10    (was: unlimited)
min_samples_split = 30    (was: 2)
min_samples_leaf  = 20    (was: 1)
ccp_alpha         = 0.001 (cost-complexity pruning)
```

*Logistic Regression:*
```
C       = 1.0  (inverse regularisation strength)
penalty = 'l2' (Ridge regularisation)
```

**Results after applying constraints:**

| Model | Train Accuracy | Test Accuracy | Gap |
|---|---|---|---|
| Random Forest | 96.6% | 96.3% | **0.26%** ✓ |
| XGBoost | 97.4% | 96.4% | **1.02%** ✓ |
| Logistic Regression | 96.6% | 96.5% | **0.14%** ✓ |
| Decision Tree | 96.4% | 96.2% | **0.23%** ✓ |

All four gaps are now below 1.1%. The models generalise correctly to unseen data.

**Faculty analogy:** Overfitting is like a student who memorises the exact questions and answers from last year's paper. They score 100% if you give them the same paper but fail on any new questions about the same topic. Limiting tree depth is like telling the student — "you cannot write more than 10 lines per answer." It forces them to focus on the concept, not the specific memorised sentences.

---

### Issue 4 — Identical Results Across Models

**What happened:**

After the initial noise injection (using random seed = 42), cross-validation results for Random Forest and XGBoost were suspiciously identical to four decimal places:

| CV Fold | Random Forest | XGBoost |
|---|---|---|
| Fold 1 | 0.9666 | 0.9666 |
| Fold 2 | 0.9639 | 0.9639 |
| Fold 3 | 0.9657 | 0.9657 |
| Fold 4 | 0.9661 | 0.9661 |
| Fold 5 | 0.9647 | 0.9647 |

Two structurally different algorithms — an ensemble of independent decision trees vs. a sequential gradient-boosted ensemble — producing identical fold-by-fold results is statistically impossible under normal conditions.

**Root cause:**

The Gaussian noise added in Issue 1's fix used a single uniform distribution across all features. This created a noise pattern that, for random seed 42, produced a dataset where both tree-based methods converged to the same decision boundary. The dataset lacked sufficient feature-level variation to push the two algorithms onto different paths.

**Fix applied:**

Feature-specific realistic noise was introduced, modelled on actual 802.11 signal behaviour:
- `frame_rate`: multiplied by U(0.90, 1.10) — rate jitter
- `rssi`: added N(0, 3) — standard ±3 dBm signal variation
- `throughput`: multiplied by U(0.85, 1.15) — layer-2 throughput fluctuation
- `seq_variance`: added N(0, 10) — realistic sequence number drift

In addition, XGBoost's hyperparameters were made intentionally different from Random Forest's (depth 8 vs 15, learning rate 0.05, subsampling at 70%) so the two algorithms would explore the feature space differently.

**Results after fix:**

| Model | CV Accuracy |
|---|---|
| Random Forest | 96.3% |
| XGBoost | 96.4% |
| Logistic Regression | 96.5% |
| Decision Tree | 96.2% |

Each model now produces a genuinely distinct result — the ensemble voting is now meaningful, not redundant.

**Faculty analogy:** If four consultants give the same recommendation word-for-word, they either copied each other or the problem was too simple. A committee of four should show some variation in perspective. We ensured our four models saw the data differently — like four consultants with different specialisations — so their combined vote actually adds value over any single model alone.

---

### Issue 5 — Only 6 of 13 Features Were Statistically Significant

**What happened:**

Mann-Whitney U tests were run on all 13 features to check whether the distribution of each feature was significantly different between the attack class and the normal class (significance threshold: p < 0.05, with Mutual Information scores computed separately):

**Statistically significant features (p < 0.05):**

| Feature | Mutual Information Score | Effect Size |
|---|---|---|
| `reason_code` | 0.577 | Large |
| `mean_interval` | 0.480 | Large |
| `throughput` | 0.450 | Large |
| `victim_count` | 0.380 | Large |
| `seq_variance` | 0.320 | Large |
| `frame_rate` | 0.290 | Medium |

**Not statistically significant (p > 0.05):**

| Feature | Mutual Information Score | Effect Size |
|---|---|---|
| `rssi` | 0.02 | Small |
| `rssi_delta` | 0.01 | Small |
| `hour` | 0.01 | Small |
| `day_of_week` | 0.01 | Small |
| `channel` | 0.01 | Small |
| `time_since_legit` | 0.02 | Small |
| `assoc_duration` | 0.01 | Small |

**Decision — keep all 13 features:**

Despite the low individual significance of seven features, a decision was made to retain the full set. The reasoning is grounded in how ensemble tree models handle feature selection:

1. **Tree-based models self-select**: Random Forest and XGBoost use information gain and gain ratio criteria at each split. A feature with low overall statistical significance will simply never be chosen as a split criterion in any tree — it is effectively filtered out automatically, with no accuracy cost.
2. **Logistic Regression's L2 regularisation** shrinks weak coefficients toward zero during training, achieving the same effect mathematically.
3. **Feature interaction**: A feature that is individually weak may be strong in combination. For example, `hour = 3AM` alone does not indicate an attack. But `hour = 3AM` combined with `frame_rate > 200` and `reason_code = 7` together strongly indicate an automated overnight attack. Tree models capture such interactions naturally through multi-level splits.
4. **Robustness for edge cases**: Keeping broader features handles unusual attack scenarios — for instance, an attack on a non-standard channel — that the six significant features alone might miss.

**Faculty analogy:** In a medical diagnosis system, blood pressure alone might not diagnose a condition, but blood pressure combined with a specific enzyme level combined with patient age might. Features that appear insignificant in isolation can become decisive in combination. Tree models handle this automatically — we lose nothing by keeping them.

---

### Issue 6 — Class Balance Verification

**Verification performed:**

Before finalising training, the class distribution was verified at every stage of the pipeline:

| Stage | Normal Samples | Attack Samples | Balance |
|---|---|---|---|
| Full dataset | 50,000 (50%) | 50,000 (50%) | Balanced |
| Training set (80%) | 40,020 | 39,980 | Balanced |
| Test set (20%) | 10,007 | 9,993 | Balanced |

**Why balance matters:**

A dataset with, for example, 95% Normal and 5% Attack samples would allow a trivial classifier — one that always predicts "Normal" — to achieve 95% accuracy while catching zero attacks. Such a model is useless for security purposes.

The 50-50 balance forces all four models to learn both classes with equal emphasis. No class can be ignored without a direct drop in accuracy.

**Additional safeguard:** All four models were trained with `class_weight='balanced'` (or the XGBoost equivalent `scale_pos_weight`). This parameter instructs the training algorithm to assign higher penalty to misclassifications in the minority class — even if slight imbalances appeared after the noise and label-flip operations described earlier, the models would still weight both classes equally.

---

## 5.5 ML-3: Model Training and Evaluation

After all preprocessing issues were resolved, the four models were trained using **5-fold stratified cross-validation** on the 80,000-sample training set. The trained models were then evaluated on the held-out 20,000-sample test set.

**Final test-set results:**

| Model | Test Accuracy | Precision | Recall | F1-Score | Train-Test Gap |
|---|---|---|---|---|---|
| Random Forest | 96.3% | 96.1% | 96.5% | 96.3% | 0.26% |
| XGBoost | 96.4% | 96.2% | 96.6% | 96.4% | 1.02% |
| Logistic Regression | 96.5% | 96.4% | 96.6% | 96.5% | 0.14% |
| Decision Tree | 96.2% | 96.0% | 96.4% | 96.2% | 0.23% |

All four models were evaluated independently using:
- Confusion matrix (True Positive, True Negative, False Positive, False Negative counts)
- ROC curve with AUC score
- 5-fold cross-validation accuracy mean and standard deviation

**Ensemble voting weights (used in production Flask API):**

| Model | Weight | Rationale |
|---|---|---|
| Random Forest | 0.30 | Highest aggregate stability across folds |
| XGBoost | 0.30 | Highest peak accuracy |
| Logistic Regression | 0.20 | Simplest model, fastest inference |
| Decision Tree | 0.20 | Single-tree baseline for interpretability |

The final prediction at runtime is computed as:

```
confidence_score = Σ (model_prediction × model_weight) / total_weight × 100
```

If `confidence_score > 50` → verdict: **ATTACK**  
If `confidence_score ≤ 50` → verdict: **NORMAL**

**Model export:**

All four trained models were serialised using Python's `pickle` module and saved as `.pkl` files:
- `decision_tree_model.pkl`
- `random_forest_model.pkl`
- `logistic_regression_model.pkl`
- `xgboost_model.pkl`
- `standard_scaler.pkl` (the `StandardScaler` fit on the training set, applied identically to all inference inputs)

These files are loaded at startup by the Flask ML API (`ml-api/app.py`) and held in memory for zero-latency inference on incoming feature vectors from the Spring Boot backend.

---

## 5.6 Summary of All Issues and Resolutions

| # | Issue | Root Cause | Fix Applied | Outcome |
|---|---|---|---|---|
| 1 | 100% accuracy — data leakage | `reason_code` perfectly separated classes | 5% Gaussian noise, 2% label flips, 3% value swaps | Accuracy normalised to 96.4% |
| 2 | Multicollinearity (r = 0.92) | `mean_interval` and `std_interval` nearly identical | Dropped `std_interval`; 14 → 13 features | <0.1% accuracy loss, no multicollinearity |
| 3 | Overfitting (12.6% gap) | Unlimited depth, no minimum sample constraints | `max_depth`, `min_samples_leaf`, L1/L2 regularisation | All gaps reduced to <1.1% |
| 4 | Identical results across models | Uniform noise, same random seed for both tree models | Feature-specific noise, differentiated hyperparameters | Each model gives distinct, independent result |
| 5 | Only 6/13 features significant | 7 features had low individual statistical power | Retained all 13 — models auto-filter via split criteria | No accuracy impact, full coverage retained |
| 6 | Class imbalance risk | Label-flip noise could skew distribution | 50-50 dataset + `class_weight='balanced'` | Both classes weighted equally throughout training |

---

## 5.7 Methodology Note (For Research Paper Section)

During model development, several data quality and training challenges were encountered and systematically resolved. Data leakage was detected when all four models achieved 100% accuracy, traced to perfect class separation in the `reason_code` feature. Controlled Gaussian noise at 5% of feature standard deviation and 2% label perturbation were introduced to simulate real-world data imperfections.

Multicollinearity between `mean_interval` and `std_interval` (r = 0.92) was resolved by removing `std_interval` after experimental validation across three approaches demonstrated less than 0.1% accuracy impact.

Overfitting, which initially manifested as a 12.6% training-to-test accuracy gap in Random Forest and 17.5% in Decision Tree, was mitigated through depth limiting (`max_depth` = 10–15), minimum sample constraints (`min_samples_leaf` = 10–20), and L1/L2 regularisation across all four models. The training-test gap was reduced to below 1.1% for all classifiers.

Model diversity was ensured through feature-specific noise injection and differentiated hyperparameter configurations, preventing convergence to identical decision boundaries — a necessary condition for the weighted ensemble voting to add value over any single model.

These iterative refinements demonstrate rigorous experimental methodology, resulting in four robust classifiers achieving 96.2%–96.5% test accuracy with minimal overfitting and a practical, deployable ensemble confidence score for real-time deauthentication attack detection.

---

*End of Chapter 5*
