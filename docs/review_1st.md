# FIRST REVIEW REPORT

**KIT-KALAIGNARKARUNANIDHI INSTITUTE OF TECHNOLOGY**
(An Autonomous Institution)
COIMBATORE-641402.

**DEPARTMENT OF MASTER OF COMPUTER APPLICATIONS**

**FINAL SEMESTER PROJECT**

---

**Submitted by:** Supreeth Ragavendra S
**Reg. No.:** [Your Registration Number]
**Guide:** Shanthini K.S
**Title of the project:** Real-Time Wi-Fi Deauthentication Attack Detection and Prevention Using Multi-Layered Analysis and Autonomous Defense

---

### 1. NEED FOR THE STUDY
**Why this study has been undertaken:**
Wi-Fi networks are highly vulnerable to deauthentication attacks because IEEE 802.11 management frames are transmitted in cleartext without cryptographic authentication. Attackers can trivially spoof MAC addresses and inject forged deauthentication frames, instantly disconnecting all clients from a wireless access point in under 100 milliseconds. While the 802.11w amendment (Protected Management Frames) attempts to address this, its real-world adoption is low, and even PMF-enabled networks suffer from airtime contention and CPU overhead during flood attacks. A robust, autonomous detection and prevention mechanism that does not rely on naive MAC blocking (which mistakenly blocks the spoofed victim) is urgently needed.

### 2. REVIEW OF LITERATURE
- **Study of existing systems:** Current Wireless Intrusion Detection Systems (WIDS) like Kismet and Waidps are largely passive; they detect anomalies but fail to execute autonomous prevention.
- **Research papers referred:**
  - Bellardo & Savage (2003): Highlighted the fundamental flaws in 802.11 management frame architecture.
  - Aminanto et al. (2018): Applied deep learning for Wi-Fi impersonation detection but lacked physics-based spoofing verification.
  - Btoush (2024): Demonstrated that most ML-based wireless IDS fail to operate in real-time due to high processing overhead.
- **Existing tools/technologies:** Attack tools like `aireplay-ng`, `MDK4`, and `ESP8266 Deauther` are widely accessible, making the attacks trivial to execute.
- **Limitations of current systems:** Single-layered detection leads to high false positive rates. Most importantly, current prevention systems attempt to block the source MAC address, which in a deauthentication attack is always spoofed (typically spoofing the victim or AP), inadvertently assisting the attacker.
- **Need for proposed system:** A multi-layered approach combining heuristic rules, machine learning, and physical layer characteristics (TSF/RSSI) that leverages attack-vector suppression (frame rate limiting) instead of MAC isolation.

### 3.1 PRIMARY OBJECTIVE
To develop, implement, and evaluate a real-time, multi-layered intrusion detection and autonomous prevention system capable of identifying and mitigating IEEE 802.11 deauthentication attacks with sub-500ms latency, utilizing a zero-MAC-blocking defense philosophy.

### 3.2 SECONDARY OBJECTIVES
- To train and integrate a machine learning ensemble (Random Forest, XGBoost, Decision Tree, Logistic Regression) capable of high-accuracy attack classification.
- To implement physics-based spoofing verification utilizing AP TSF clock drift and RSSI signal profiling.
- To design a Kill Chain State Machine (KCSM) that tracks persistent attacker behavior to defeat low-and-slow evasion tactics.
- To construct a comprehensive full-stack platform (React, Spring Boot, Python) for real-time monitoring and administrative control.

### 4. PROBLEM STATEMENT
- **What is the problem?** The IEEE 802.11 standard lacks built-in authentication for management frames. Attackers exploit this to forge deauthentication frames, forcing client disconnections.
- **Who faces the problem?** Educational campuses, corporate enterprises, hospitals, and residential users relying on continuous Wi-Fi connectivity.
- **Why does it need a solution?** These attacks cause severe network downtime, disrupt essential services, and are frequently used as the crucial first step to capture WPA handshakes for offline password cracking.

### 5. PROPOSED SYSTEM
- **Overview of the proposed solution:** A three-layer parallel detection engine (Heuristics, ML Ensemble, Physics-based) integrated with an autonomous four-level prevention engine.
- **Advantages over existing system:** Completely avoids false-positive MAC blocking by suppressing the attack vector directly at the kernel bridge level. Achieves sub-200ms victim reconnection.
- **Expected benefits:** Guaranteed Wi-Fi service continuity, zero reliance on vulnerable MAC address identification, and comprehensive real-time situational awareness via a web dashboard.

### 6. METHODOLOGY
The project utilises a microservices architecture operating simultaneously at the network and application layers:
1. **Network Layer:** A Python/Scapy packet sniffer operates in monitor mode, capturing and pre-processing 802.11 frames.
2. **Detection Layer:** Incoming data is routed through three parallel layers: rule-based statistics (frame sequence/rate), an ML Flask API (ensemble voting), and physics validators (RSSI/TSF).
3. **Prevention Layer:** An autonomous engine escalates through four stages—from passive forensics to ebtables-based kernel rate limiting, BSSID-clone honeypot deployment, and automatic `nmcli/wpa_cli` victim reconnection.
4. **Presentation Layer:** A Java Spring Boot API aggregates state and pushes real-time telemetry via Server-Sent Events (SSE) to a React SPA.

### 7. TECHNOLOGY STACK
- **Layer:** Technology
- **Frontend:** React.js, TypeScript, Tailwind CSS, Vite
- **Backend:** Java 17, Spring Boot, Spring Data JPA
- **Machine Learning API:** Python, Flask, Scikit-Learn, XGBoost, Pandas
- **Database:** MySQL (Production) / H2 (Development)
- **Tools:** Scapy, ebtables, hostapd, Git, Maven
- **OS/Environment:** Linux (Ubuntu 22.04), Network Adapters supporting Monitor Mode (Atheros AR9271)

### 8. WORK PLAN/PROJECT SCHEDULE
| Phase | Duration | Status |
| :--- | :--- | :--- |
| **Requirement Gathering** | 2 Weeks | Completed |
| **Design (Architecture & ML)**| 2 Weeks | Completed |
| **Development** | 6 Weeks | Completed / Ongoing |
| **Testing** | 2 Weeks | In Progress |
| **Documentation** | 2 Weeks | In Progress |

### 9. WORK DONE SO FAR
- Implemented the Python packet capture engine using Scapy for live traffic ingestion.
- Trained and serialized the Machine Learning ensemble model on an augmented 1,00,000-sample dataset, achieving 96.5% accuracy.
- Deployed the Flask ML inference API.
- Developed the Java Spring Boot REST API and configured database constraints.
- Built the React frontend dashboard featuring real-time detection feeds and blocked MAC visualizations via SSE.
- Implemented Phase 1 of the Prevention Engine, including the Kill Chain State Machine and alert throttling.

### 10. EXPECTED OUTCOME
- **What the system will achieve?** Real-time, automated suppression of deauthentication attacks within 500ms, effectively neutralizing tools like `aireplay-ng` and `MDK4` without human intervention.
- **How it improves existing process?** Shifts the paradigm from passive logging and flawed MAC-blocking to active, vector-based defense. It introduces physics-based spoof verification and ensures clients remain connected even during intense, ongoing flood attacks.

---
**Signatures**

<br><br><br>

___________________________<br>
**Signature of the Candidate**

<br><br><br>

___________________________<br>
**Signature of the Guide**

<br><br><br>

___________________________<br>
**Signature of the Project Coordinator**

<br><br><br>

___________________________<br>
**Signature of the HOD-MCA**
