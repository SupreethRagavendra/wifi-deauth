# CHAPTER 4: SOFTWARE DESCRIPTION

## 4.1 Introduction

This chapter describes the software tools, programming languages, frameworks, databases, and libraries we used to build the Real-Time Wi-Fi Deauthentication Attack Detection and Prevention System. The selection of each tool was driven by specific requirements of the system — network-level packet capture, machine learning inference, real-time web communication, and secure multi-user management. Each decision is explained in this chapter.

The system is a multi-process distributed application integrating a JVM-based backend, a Python detection engine, a browser-based React frontend, a relational database, and two external cloud notification services. Each layer was built using the most appropriate tool for that layer's requirements. Table 4.1 provides a complete summary.

**Table 4.1: Complete Technology Stack Summary**

| Layer | Technology | Version | Purpose |
|---|---|---|---|
| Operating System | Ubuntu Linux | 22.04 LTS | Monitor mode, kernel tools |
| Backend API | Java + Spring Boot | 17 LTS / 3.2.1 | REST API, authentication, SSE, DB |
| Detection Engine | Python + Scapy | 3.11 / 2.5.0 | Raw 802.11 capture, 3-layer analysis |
| ML Inference API | Python + Flask | 3.11 / 3.0.0 | Serve trained models via HTTP |
| Frontend UI | TypeScript + React | 5.x / 18.2 | Real-time dashboard, role filtering |
| Database | MySQL | 8.0.35 | Persistent storage of all data |
| ML Training | scikit-learn + XGBoost | 1.4.x / 2.0.x | Train 4 classifiers |
| Email Alerts | Brevo API | v3 | HTML alert emails |
| SMS Alerts | SMSLocal API | REST v1 | SMS for CRITICAL events |
| Cloud DB Host | Aiven MySQL | Managed | SSL, backups, no self-hosting |

---

## 4.2 Operating System

We developed and deployed the entire system on **Ubuntu 22.04 LTS (Jammy Jellyfish)**. Linux was the only practical choice for this project for several reasons.

First, Wi-Fi packet capture in monitor mode — which is mandatory for detecting deauthentication frames — requires direct access to the **nl80211** wireless subsystem. On Linux, tools like `airmon-ng`, `iwconfig`, and `iw` can place a Wi-Fi adapter into monitor mode with standard commands. On Windows, this requires proprietary, hardware-specific drivers and is generally unreliable for raw packet capture.

Second, the **Scapy** packet manipulation library, which forms the backbone of our detection engine, functions best under Linux where it can access raw sockets without restriction. On Windows and macOS, Scapy requires Npcap and has known limitations with 802.11 frame injection and capture.

Third, the kernel-level prevention tools we used — specifically `ebtables` for bridge-level packet rate limiting and `hostapd` for access point management — are Linux-only utilities. There is no cross-platform equivalent for kernel bridge filtering.

**Table 4.2: Operating System Comparison**

| Feature | Ubuntu 22.04 LTS | Windows 11 | macOS Ventura |
|---|---|---|---|
| Monitor mode support | Full (nl80211) | Requires NDIS driver | Partial, no injection |
| Scapy raw socket | AF_PACKET natively | Needs Npcap | Limited |
| ebtables kernel filter | Built-in | Not available | Not available |
| hostapd (fake AP) | apt install | Not supported | Not supported |
| airmon-ng | Full support | Not available | Not available |6.18.9+kali-
| Spring Boot / Java | Yes | Yes | Yes |
| React / Node.js | Yes | Yes | Yes |
| **Overall suitability** | **Best choice** | Incompatible | Partially incompatible |

**Kernel version requirement:** Linux kernel 5.15 or above is needed to reliably support the ath9k driver used by the TP-Link TL-WN722N adapter in monitor mode. Our development machine ran kernel **6.18.9+kali-amd64** (verified with `uname -r`). This is well above the minimum and provided full `ath9k_htc` driver support without any additional configuration.

[INSERT FIGURE 4.1: Terminal screenshot — `uname -r` confirming kernel version and `airmon-ng start wlan1` placing the adapter into monitor mode]

---

## 4.3 Programming Languages

### 4.3.1 Java (Version 17 LTS)

We used Java 17 for the backend API server. Java 17 is a Long-Term Support (LTS) release, which means it receives security patches and stability updates until 2029. This made it an appropriate choice for a production-oriented project.

The Spring Boot framework — which we discuss in Section 4.6.1 — runs on the JVM, and Java 17 provides several useful language features we used throughout the backend, including sealed classes, records for clean DTO definitions, switch expressions, and text blocks for SQL and JSON string formatting.

We chose Java for the backend primarily because Spring Boot's ecosystem provides mature, well-documented solutions for every requirement we had: RESTful APIs, database ORM, JWT security, SSE streaming, and email integration. The strong static typing of Java also reduced runtime errors significantly during development.

### 4.3.2 Python (Version 3.11)

Python 3.11 powers the entire detection and prevention subsystem. We chose Python for two main reasons: the **Scapy** library for raw 802.11 packet capture and the **scikit-learn** ecosystem for machine learning.

Python 3.11 introduced several performance improvements over 3.10 — particularly a faster interpreter (the "Faster CPython" project) — which mattered for our detection loop, which processes hundreds of frames per second.

We also chose Python because it allows rapid prototyping of detection algorithms before finalising them. The detection logic went through many iterations during development, and Python's interactive REPL and notebook support made that process much faster than it would have been in Java.

### 4.3.3 TypeScript / JavaScript (React 18)

We used **TypeScript** on the frontend instead of plain JavaScript. TypeScript adds static type checking to JavaScript, which catches a whole class of bugs at compile time — particularly when handling the JSON responses from our backend API. Since we had multiple data structures (events, packets, detection results, prevention states), the ability to define interfaces for each response type and have the compiler warn us about mismatches was very valuable.

**React 18** was chosen for the frontend framework because of its component-based architecture, which made it natural to build the dashboard as a set of reusable panels (Detection Feed, Packet Table, ML Statistics, Prevention Status). React's virtual DOM also ensures that updating specific parts of the dashboard during live SSE events does not cause the entire page to re-render.

**Table 4.3: Programming Language Comparison**

| Criterion | Java 17 (Backend) | Python 3.11 (Detection) | TypeScript (Frontend) |
|---|---|---|---|
| Type safety | Strong static | Optional type hints | Compile-time types |
| Raw 802.11 packet access | Not suitable | Scapy (AF_PACKET) | N/A |
| ML ecosystem | Limited | sklearn, XGBoost | N/A |
| Web / API framework | Spring Boot | Flask (lightweight) | React 18 |
| Database access | Spring Data JPA | Direct SQL / pymysql | N/A |
| Real-time SSE | SseEmitter | N/A | EventSource API |
| Why we chose it | Enterprise API server | Packet capture + ML | Live dashboard UI |

---

## 4.4 Database Management System

We used **MySQL 8.0** as the relational database. MySQL was chosen over alternatives like PostgreSQL because:

1. The Spring Data JPA with Hibernate ORM has first-class, well-tested MySQL dialect support.
2. MySQL 8.0 supports window functions, CTEs, and full JSON column types, which we found useful for storing variable-length detection metadata.
3. For cloud deployment, we used **Aiven's managed MySQL** service, which provides automatic backups, SSL-enforced connections, and monitoring without requiring us to manage a database server ourselves.

**Table 4.4: Database Comparison**

| Feature | MySQL 8.0 | PostgreSQL | SQLite |
|---|---|---|---|
| Spring JPA dialect support | First-class | Supported | Limited |
| Cloud managed hosting (Aiven) | Available | Available | Not managed |
| JSON column type | JSON type | JSONB | Text only |
| SSL enforced connections | Yes | Yes | No |
| Concurrent write performance | InnoDB MVCC | MVCC | File-level lock |
| Suitability for our scale | Best fit | Overkill | Not suitable |

The database contains the following primary tables:

**Table 4.5: Database Tables Description**

| Table | Key Columns | Purpose |
|---|---|---|
| `users` | id, email, password_hash, role | User accounts and roles |
| `institutes` | id, name | Organisational grouping |
| `wifi_networks` | ssid, bssid, channel, institute_id | Registered Wi-Fi networks |
| `user_wifi_mapping` | user_id, network_id | Viewer-to-network access |
| `detection_events` | src_mac, dst_mac, severity, scores | All detected anomalies |
| `scan_results` | event_id, raw_packet_data | Per-packet raw records |
| `alert_logs` | event_id, channel, status, sent_at | Email/SMS delivery log |
| `prevention_events` | event_id, defense_level, actions | All prevention actions |

[INSERT FIGURE 4.2: MySQL Workbench / DBeaver screenshot — schema browser with `detection_events` table selected and sample rows visible]

---

## 4.5 Development Tools

### 4.5.1 Integrated Development Environments

We used **IntelliJ IDEA Community Edition** for all backend Java development. IntelliJ understands Spring-specific annotations (`@RestController`, `@Entity`, `@Service`, `@Repository`) and provides auto-completion for Spring configuration files. Its debugger was used extensively during development of the JWT authentication flow and the SSE streaming endpoint.h

We used **Visual Studio Code** for the Python detection engine and the React frontFIGcend. VS Code's Pylance extension provides linting, type inference, and Jupyter notebook support, which we used during ML model training. ESLint and Prettier extensions enforced consistent code formatting.

**Table 4.6: IDE Feature Comparison**

| Feature | IntelliJ IDEA | VS Code |
|---|---|---|
| Spring Boot support | Native, deep integration | Via extension |
| Java debugger | Full step-through | Via Java Debug extension |
| Python / Pylance | Via plugin | First-class support |
| React / TypeScript | Basic | First-class |
| ML Jupyter notebooks | Not suitable | Inline notebook cells |
| Cost | Community Edition (free) | Fully free |
| Used in our project | Java backend | Python detection + React |

[INSERT FIGURE 4.3: IntelliJ IDEA screenshot — Spring Boot project tree on left, `AuthController.java` open in editor]

[INSERT FIGURE 4.4: VS Code screenshot — `packet_sniffer.py` open with Pylance type hints visible]

### 4.5.2 Version Control

We used **Git** for version control with **GitHub** as the remote repository. We maintained branches: `main` (stable), `backend-dev`, and `frontend-dev`. Feature branches (e.g., `feature/honeypot`, `feature/kill-chain`) were merged via pull requests. Commit messages followed the Conventional Commits standard: `feat:`, `fix:`, `docs:`, `refactor:`.

[INSERT FIGURE 4.5: GitHub repository page — commit history with conventional commit messages and branch list]

### 4.5.3 API Testing

We used **Postman** throughout development to test every REST API endpoint. We built a chained collection (`module1-SUCCESS-ONLY.json`) where each request automatically extracts the JWT from the login response and attaches it to subsequent requests via environment variables.

[INSERT FIGURE 4.6: Postman screenshot — collection list on left, 200 OK login response with JWT on right]

---

## 4.6 Frameworks and Libraries

### 4.6.1 Backend Frameworks

**Spring Boot 3.2.1** is the main backend framework. It provides auto-configuration, an embedded Tomcat server, and a large ecosystem of starter dependencies that handle most boilerplate setup. We used the following Spring Boot modules:

**Table 4.7: Spring Boot Starter Dependencies**

| Starter / Library | Group ID | Purpose |
|---|---|---|
| spring-boot-starter-web | org.springframework.boot | REST controllers, JSON mapping |
| spring-boot-starter-security | org.springframework.boot | JWT filter chain, role enforcement |
| spring-boot-starter-data-jpa | org.springframework.boot | Repository interfaces, ORM |
| spring-boot-starter-mail | org.springframework.boot | Brevo SMTP email integration |
| mysql-connector-j | com.mysql | MySQL JDBC driver |
| jjwt-api / impl / jackson | io.jsonwebtoken | JWT generation and validation |
| lombok | org.projectlombok | Reduce boilerplate (getters, builders) |

- **Spring Security with JWT**: Each login returns a signed JWT (256-bit secret, 24h expiry). The `JwtAuthFilter` validates signature and expiry on every request.
- **Spring Data JPA with Hibernate**: Entity classes (`DetectionEvent`, `WifiNetwork`, `User`) are mapped to tables automatically via annotations.
- **Spring SSE (SseEmitter)**: The backend pushes live events to the React frontend using Server-Sent Events — no WebSocket server needed.

### 4.6.2 Frontend Frameworks

**Table 4.8: Frontend Package Summary**

| Package | Version | Purpose |
|---|---|---|
| react | 18.2.0 | Core UI component system |
| react-router-dom | 6.x | Client-side page routing |
| @tanstack/react-query | 5.x | Data fetching, caching, background refresh |
| tailwindcss | 3.x | Utility CSS — no custom CSS files needed |
| axios | 1.x | HTTP requests to backend API |
| react-hot-toast | 2.x | Toast notifications |
| recharts | 2.x | Accuracy and score trend charts |
| lucide-react | Latest | Icon library |
| typescript | 5.x | Compile-time type checking |

Each page maps to one system module:

| Page | Route | Roles | Content |
|---|---|---|---|
| Login | `/login` | Public | Email + password form |
| Admin Dashboard | `/dashboard` | Admin | Summary stat cards |
| WiFi Management | `/wifi` | Admin | Register / list networks |
| User Management | `/users` | Admin | Create users, assign networks |
| Detection Monitor | `/detection` | Both | Live SSE events, ML stats |
| Prevention Dashboard | `/prevention` | Both | 3 defence level cards |
| Forensic Reports | `/reports` | Admin | Download PCAP + PDF |

### 4.6.3 Machine Learning Libraries

**Table 4.9: ML Library Versions and Usage**

| Library | Version | Used for |
|---|---|---|
| scikit-learn | 1.4.0 | Random Forest, Decision Tree, Logistic Regression, StandardScaler |
| xgboost | 2.0.3 | XGBoost classifier |
| numpy | 1.26.x | Feature arrays, Gaussian noise injection |
| pandas | 2.1.x | Dataset loading, augmentation, inspection |
| joblib | 1.3.x | Serialise models to `.pkl` for Flask |
| flask | 3.0.0 | HTTP server exposing `/predict` endpoint |
| matplotlib / seaborn | 3.8.x | Training charts (confusion matrix, curves) |

### 4.6.4 Packet Capture Libraries

**Table 4.10: Packet Capture Library Comparison**

| Library | Language | Monitor mode | Injection | Used |
|---|---|---|---|---|
| Scapy | Python | Yes | Yes | Yes — detection engine |
| pyshark | Python | Yes (via tshark) | No | No — heavier overhead |
| libpcap | C | Yes | No | Yes — Scapy backend |
| Wireshark tshark | CLI | Yes | No | No — not scriptable |
| pcapy | Python | Yes | No | No — unmaintained |

We use Scapy's `AsyncSniffer` with BPF filter `type mgt subtype deauth` so only deauthentication frames reach the detection logic, keeping CPU and memory load low.

---

## 4.7 Hardware Requirements

The critical hardware component in this project is the **TP-Link TL-WN722N v1** Wi-Fi USB adapter. This specific adapter uses the **Atheros AR9271** chipset, which is one of the few chipsets that fully supports:

- **Monitor mode**: Passively captures all 802.11 frames on a channel, including frames not addressed to our device.
- **Packet injection**: Allows us to transmit crafted frames, which is needed for the fake handshake flood in Level 4 defence.
- **Driver support (ath9k_htc)**: The `ath9k_htc` kernel driver is open-source and part of the mainline Linux kernel, meaning no third-party driver installation is needed on Ubuntu 22.04.

> **Important note:** The TP-Link TL-WN722N v2 and v3 use a different Realtek chipset (RTL8188EUS) and do NOT support monitor mode by default. Only v1 (with the AR9271 chip) is compatible.

**Table 4.11: TP-Link TL-WN722N Version Comparison**

| Specification | v1 (Our choice) | v2 | v3 |
|---|---|---|---|
| Chipset | Atheros AR9271 | Realtek RTL8188EUS | Realtek RTL8188EUS |
| Kernel driver | ath9k_htc (built-in) | rtl8188eus (must compile) | rtl8188eus (must compile) |
| Monitor mode | Full support | No (out of box) | No (out of box) |
| Packet injection | Full support | No | No |
| External antenna | Yes (3 dBi) | No | No |
| How to identify | Has removable antenna | No antenna | No antenna |

**Table 4.12: System Hardware Specifications**

| Component | Our Machine | Minimum Required |
|---|---|---|
| CPU | Intel Core i5-10th Gen, 4 cores | Dual-core 1.5 GHz |
| RAM | 8 GB DDR4 | 4 GB |
| Storage | 512 GB SSD | 10 GB free |
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| Wi-Fi interfaces | Internal (managed) + TL-WN722N (monitor) | 1 USB Wi-Fi adapter |
| USB | USB 3.0 | USB 2.0 |
| Linux kernel | 6.18.9+kali-amd64 | kernel >= 5.15 |

---

## 4.8 External Services

**Brevo (formerly Sendinblue):** We integrated the Brevo Transactional Email API (v3) to send HTML attack alert emails. When a CRITICAL or HIGH severity attack is detected, the `NotificationService` POSTs to `https://api.brevo.com/v3/smtp/email` with the formatted alert body. A per-attacker 10-minute cooldown and a daily limit of 50 emails prevent exceeding the free tier.

**SMSLocal API:** For SMS alerts on CRITICAL events only. Each SMS is kept under 160 characters to avoid multi-part charges.

**Aiven Cloud MySQL:** Managed MySQL with automated daily backups, SSL-enforced connections, and web console access — no self-hosted database server needed.

**Table 4.13: External Services Comparison**

| Feature | Brevo (Email) | SMSLocal (SMS) |
|---|---|---|
| Protocol | REST HTTPS | REST HTTPS |
| Free tier | 300 emails/day | Charged per SMS |
| India phone numbers | Email worldwide | Yes, India numbers |
| HTML support | Full HTML email | Text only |
| Throttling in our system | 10 min cooldown + 50/day cap | CRITICAL events only |
| Used for | All HIGH/CRITICAL alerts | CRITICAL only |

[INSERT FIGURE 4.7: Brevo dashboard screenshot — sent email log with alert emails visible (API key blurred)]

---
`
# CHAPTER 5: PROJECT DESCRIPTION

## 5.1 Introduction

This chapter presents the complete architecture of the Real-Time Wi-Fi Deauthentication Attack Detection and Prevention System. We describe each module in detail, including the data flow between them, the algorithms used for detection and prevention, and the database design. The system is built as a distributed, multi-process application where each component has a clearly defined responsibility.

---

## 5.2 System Architecture

### 5.2.1 High-Level Architecture

The system follows a **three-tier client-server architecture**:

1. **Presentation Tier**: React/TypeScript single-page application running in the user's browser.
2. **Application Tier**: Spring Boot REST API (port 8080), Python ML Flask API (port 5000), and Python Detection/Prevention Engine.
3. **Data Tier**: MySQL database storing all users, events, packets, and alerts.

The detection engine (Python/Scapy) runs as a separate process on the same machine as the Wi-Fi adapter. It sends detected events to the Spring Boot backend via HT`TP POST. The backend stores the event, evaluates the threat, triggers the prevention engine, and streams the event to all connected dashboard clients via SSE.

### 5.2.2 Component Description

| Component | Technology | Responsibility |
|---|---|---|
| **Frontend** | React 18, TypeScript | Dashboard UI, real-time event display |
| **Backend API** | Spring Boot 3.2 | REST API, authentication, SSE, database |
| **Detection Engine** | Python, Scapy | Monitor mode capture, Layer 1/2/3 analysis |
| **ML Flask API** | Python, Flask, scikit-learn | Layer 2 ML inference endpoint |
| **Prevention Engine** | Python | 3-level autonomous defence actions |
| **Database** | MySQL 8.0 | Persistent storage of all system state |
| **Alert Service** | Brevo, SMSLocal | Email and SMS notifications |

---

## 5.3 Module Description

### Module 1 — User & Wi-Fi Registration

Before any detection data is visible, the system requires setup via the User & Wi-Fi Registration module. Adhering to role-based access control, the system supports Admin and Viewer roles. Passwords are hashed using BCrypt, and secure JWTs (JSON Web Tokens) are utilised for API authentication via Spring Security.

Admins register the target Wi-Fi networks by providing the SSID, BSSID (router MAC address), and operating channel. This dataset, stored in the `wifi_networks` table, precisely directs the detection engine to monitor specific APs. Admins further map these registered networks to Viewer accounts using the `user_wifi_mapping` table, guaranteeing that Viewers only access events pertinent to their assigned networks.

---

### Module 2 — Packet Capture Engine

The Packet Capture Engine is the foundational data ingress point for the system. It utilises Scapy's `AsyncSniffer` bound to the monitor-mode interface (`wlan1mon`). To eliminate processing overhead and focus solely on the attack vector, a strict BPF (Berkeley Packet Filter) of `type mgt subtype deauth` is applied at the kernel level.

This engine silently observes raw 802.11 management frames in the air. For every intercepted frame, it extracts critical header metadata including the source MAC address, destination MAC address, BSSID, reason code, RSSI (signal strength), and the TSF (Timing Synchronisation Function) timestamp. This parsed data is instantly forwarded to the Detection Engine for analysis.

---

### Module 3 — Detection Engine

The Detection Engine forms the core analytical intelligence of the system, passing captured frames through a rigorous three-layer pipeline to determine the threat level:

**Layer 1 — Statistical Analysis (Heuristics):** Four parallel sub-analysers inspect a sliding window of recent frames. They evaluate the rate of deauth frames (`RateAnalyser`), sequence number anomalies (`SequenceValidator`), suspicious activity times (`TimeAnomalyDetector`), and whether the victim was even associated prior to disconnection (`SessionStateChecker`). This produces a fast baseline score (S1) under 5 milliseconds.

**Layer 2 — Machine Learning Ensemble:** If the Layer 1 score exceeds 30, the engine extracts a 13-feature vector and queries an ML Flask API. This API evaluates the vector against four trained models (Random Forest, XGBoost, Decision Tree, Logistic Regression) to generate a weighted confidence score (S2).

**Layer 3 — Physics-Based Spoofing Verification:** To differentiate legitimate AP traffic from an attacker spoofing the AP's MAC address, this layer analyses physical characteristics. It tracks TSF clock drift (identifying mismatched crystal oscillator frequencies) and profiles RSSI baselines (flagging sudden drops or spikes in signal strength that indicate a different physical location).

The final threat score aggregates these layers, with physical spoofing confirmation heavily penalising the connection score.

---

### Module 4 — Auto-Blocking Engine & Prevention

Operating autonomously upon receiving a high threat score, the Auto-Blocking Engine deploys a graduated, three-level defence mechanism. **Crucially, no MAC address is ever blocked**, as attackers spoof legitimate addresses (blocking them would aid the denial-of-service).

**Level 1 — Fast Reconnection (Score ≥ 40):** The system initiates proactive measures to keep the victim connected. It enables Pre-Association Caching (OKC), configures aggressive probe responses (beacon interval of 50ms), and triggers predictive pre-authentication by reassociating the `wpa_cli` client immediately. Forensic packet capture of the attack is also initiated.

**Level 2 — Application Resilience (Score ≥ 60):** OS-level changes are applied to prevent applications from dropping connections during brief wireless interruptions. The system tunes kernel sysctl parameters for TCP Connection Preservation, enables MPTCP (Multipath TCP) for session persistence, and increases network buffers.

**Level 3 — UX Optimization & Honeypot (Score ≥ 85):** The system masks the attack from the user by suppressing GNOME disconnection notifications and disabling power-saving mode for seamless handoffs. Additionally, a **Honeypot Deception** protocol is activated, generating 150 fake access points via `hostapd` virtual interfaces. This drastically reduces the attacker's first-try success probability to 0.67%, heavily delaying unsophisticated attack tools.

**Kill Chain State Machine:** The `KillChainStateMachine` maintains a cumulative threat score per attacker identity over time, ensuring that persistent, low-rate burst attacks eventually cross the defence thresholds.

---

### Module 5 — Alert & Notification System

To ensure administrators are immediately aware of critical security events, the Alert & Notification System dispatches out-of-band warnings:

1. **Email Alerts (Brevo API):** Formatted HTML emails containing the event timestamp, attacker MAC, victim MAC, BSSID, and confidence score are sent to the registered administrator. A per-attacker cooldown of 10 minutes and a daily limit of 50 emails prevent API exhaustion and alert fatigue.
2. **SMS Alerts (SMSLocal API):** For CRITICAL events (Score ≥ 85), immediate short text messages are dispatched to the administrator's mobile device via the SMS API.
3. **Forensics:** Comprehensive PDF reports and raw PCAP evidence files collected during the attack are made available for download via the Prevention Dashboard, aiding in post-incident analysis and legal attribution.

---

## 5.4 System Design

### 5.4.1 Input Design

Input design defines the data the system accepts from users and external components.

**I. User Registration Form (Admin / Viewer / Home User)**

| Field | Type | Validation | Example |
|---|---|---|---|
| Name | Text | Required, max 100 chars | Supreeth R |
| Email | Email | Required, unique, valid format | supreeth@reva.edu |
| Password | Password | Required, min 8 chars | ●●●●●●●● |
| Institute Name | Text | Required (Admin only) | REVA University |
| Institute Type | Dropdown | COLLEGE / SCHOOL / COMPANY / HOME | COLLEGE |
| Institute Code | Text | Required (Viewer only), 6–20 chars | REVA2024 |

**II. WiFi Network Registration Form (Admin only)**

| Field | Type | Validation | Example |
|---|---|---|---|
| SSID | Text | Required, max 32 chars | REVA-5G |
| BSSID | MAC Address | Required, format `XX:XX:XX:XX:XX:XX` | A4:CF:12:D3:44:B0 |
| Channel | Number | Optional, 1–165 | 6 |
| Security Type | Dropdown | WPA2 / WPA3 / OPEN / WEP | WPA2 |
| Location | Text | Optional | Block 3, Floor 2 |

**III. Packet Sniffer Input (API — `POST /api/packets/deauth/batch`)**

The Python sniffer sends captured 802.11 deauthentication frames as JSON:

| Field | Type | Description | Example |
|---|---|---|---|
| src | String | Source MAC of the frame | DE:AD:BE:EF:00:01 |
| dst | String | Destination MAC | CA:FE:BA:BE:00:02 |
| bssid | String | Access Point MAC | A4:CF:12:D3:44:B0 |
| signal | Integer | RSSI in dBm | −42 |
| reason | Integer | 802.11 reason code | 7 |
| timestamp | Double | Unix epoch seconds | 1709812345.678 |
| seq | Integer | 802.11 sequence number | 3042 |
| tsf | Long | Timing Sync Function µs | 982734561200 |

**IV. Viewer MAC Registration (`PUT /api/users/mac-address`)**

| Field | Type | Validation | Example |
|---|---|---|---|
| macAddress | String | Required, unique, format `XX:XX:XX:XX:XX:XX` | 3C:06:30:1A:2B:4F |

---

### 5.4.2 Output Design

Output design describes the information the system presents to users.

**I. Admin Dashboard (React Frontend)**

| Output | Description | Update Method |
|---|---|---|
| System Status | SAFE / UNDER ATTACK indicator with colour | SSE real-time push |
| Threat Level | Current score (0–100) with severity badge | SSE real-time push |
| Packets Analysed | Counter of total deauth frames processed | SSE real-time push |
| Active Attacks | Count of ongoing attack sessions | SSE real-time push |
| Detection Events Table | List of recent events with attacker MAC, victim MAC, severity, L1/L2/L3 scores, timestamp | REST API polling |
| Prevention Status | Current defence level active (Level 1/2/3) | SSE real-time push |

**II. Viewer Dashboard (Filtered)**

| Output | Description |
|---|---|
| Device Status | Whether the Viewer's registered MAC is currently under attack |
| Personal Events | Only detection events where `victim_mac` matches the Viewer's registered MAC |
| Network Info | SSID and BSSID of the assigned WiFi network |

**III. Alert Notifications (Out-of-Band)**

| Channel | Trigger | Content |
|---|---|---|
| Email (Brevo API) | Severity ≥ HIGH | HTML email with timestamp, attacker MAC, victim MAC, BSSID, confidence score |
| SMS (SMSLocal API) | Severity = CRITICAL | Short text message with attack summary and defence level |

**IV. SSE Event Stream (`GET /api/detection/stream`)**

The server pushes JSON events to all connected dashboards:

```json
{
  "type": "ATTACK_DETECTED",
  "attackerMac": "DE:AD:BE:EF:00:01",
  "victimMac": "CA:FE:BA:BE:00:02",
  "confidence": 87.5,
  "severity": "HIGH",
  "defenseLevel": "LEVEL_2",
  "timestamp": "2026-03-09T14:23:45"
}
```

---

### 5.4.3 Data Flow Diagrams (DFD)

Data Flow Diagrams for this project are documented using DeMarco & Yourdon notation in the project's `diagram.md` file. The following diagrams have been created:

1. **Admin / Home User — Level 0 (Context Diagram):** Shows the system as a single process (0) receiving credentials and configuration from the Admin, packet data from the Sniffer, and outputting alerts and defence commands.
2. **Admin / Home User — Level 1:** Decomposes into three processes: (1.0) User & Network Management, (2.0) Attack Detection, (3.0) Alert & Prevention, with data store `D1 wifi_deauth`.
3. **Institute Viewer — Level 0 (Context Diagram):** Shows the Viewer sending credentials and MAC address, receiving filtered alerts.
4. **Institute Viewer — Level 1:** Decomposes into three processes: (1.0) Login & MAC Registration, (2.0) Attack Detection, (3.0) Filtered Dashboard, with data store `D1 wifi_deauth`.

---

### 5.4.4 Entity-Relationship (ER) Diagram

The ER diagram maps all five core tables in the `wifi_deauth` MySQL database. Key relationships:

- One **institute** has many **users** (1:N).
- One **institute** monitors many **wifi_networks** (1:N).
- One **institute** logs many **detection_events** (1:N).
- One **user** creates many **wifi_networks** (1:N).
- **users** and **wifi_networks** share a many-to-many relationship via the **user_wifi_assignments** junction table.

The complete ER diagram with all columns and data types is documented in `diagram.md`.

---

### 5.4.5 Database Design

**Database:** `wifi_deauth` (MySQL 8.0)

#### Table 1: `institutes`

| Column | Data Type | Constraint | Description |
|---|---|---|---|
| institute_id | VARCHAR(36) | PRIMARY KEY | UUID identifier |
| institute_name | VARCHAR(255) | NOT NULL | Name of the organisation |
| institute_type | ENUM | NOT NULL | COLLEGE, SCHOOL, COMPANY, HOME |
| institute_code | VARCHAR(20) | UNIQUE | Join code for Viewers |
| location | VARCHAR(255) | | Physical location |
| created_at | DATETIME | AUTO | Registration timestamp |

**Sample Record:**

| institute_id | institute_name | institute_type | institute_code |
|---|---|---|---|
| a1b2c3d4-... | REVA University | COLLEGE | REVA2024 |

---

#### Table 2: `users`

| Column | Data Type | Constraint | Description |
|---|---|---|---|
| user_id | VARCHAR(36) | PRIMARY KEY | UUID identifier |
| institute_id | VARCHAR(36) | FOREIGN KEY → institutes | Organisation link |
| name | VARCHAR(255) | NOT NULL | Full name |
| email | VARCHAR(255) | UNIQUE, NOT NULL | Login email |
| password_hash | VARCHAR(255) | NOT NULL | BCrypt hashed password |
| mac_address | VARCHAR(17) | UNIQUE | Registered device MAC |
| wifi_adapter | VARCHAR(20) | DEFAULT 'wlan1' | Monitor mode interface |
| phone_number | VARCHAR(15) | | Mobile for SMS alerts |
| alerts_email | BOOLEAN | DEFAULT true | Email alert preference |
| alerts_sms | BOOLEAN | DEFAULT true | SMS alert preference |
| role | ENUM | NOT NULL | ADMIN, VIEWER, HOME_USER |
| created_at | DATETIME | AUTO | Registration timestamp |

**Sample Records:**

| user_id | name | email | role | mac_address |
|---|---|---|---|---|
| u001-... | Supreeth R | supreeth@reva.edu | ADMIN | — |
| u002-... | Student A | student@reva.edu | VIEWER | 3C:06:30:1A:2B:4F |

---

#### Table 3: `wifi_networks`

| Column | Data Type | Constraint | Description |
|---|---|---|---|
| wifi_id | VARCHAR(36) | PRIMARY KEY | UUID identifier |
| institute_id | VARCHAR(36) | FOREIGN KEY → institutes | Owner institute |
| ssid | VARCHAR(32) | NOT NULL | Network name |
| bssid | VARCHAR(17) | NOT NULL | Access point MAC |
| channel | INT | | WiFi channel (1–165) |
| security_type | ENUM | NOT NULL | WPA2, WPA3, OPEN, WEP |
| location | VARCHAR(255) | | Physical location of AP |
| created_by_user_id | VARCHAR(36) | FOREIGN KEY → users | Admin who added it |
| created_at | DATETIME | AUTO | Registration timestamp |

**Sample Record:**

| wifi_id | ssid | bssid | channel | security_type |
|---|---|---|---|---|
| w001-... | REVA-5G | A4:CF:12:D3:44:B0 | 6 | WPA2 |

---

#### Table 4: `user_wifi_assignments`

| Column | Data Type | Constraint | Description |
|---|---|---|---|
| mapping_id | VARCHAR(36) | PRIMARY KEY | UUID identifier |
| user_id | VARCHAR(36) | FOREIGN KEY → users | Viewer being assigned |
| wifi_id | VARCHAR(36) | FOREIGN KEY → wifi_networks | Network being assigned |
| assigned_at | DATETIME | AUTO | Assignment timestamp |

**Unique Constraint:** (`user_id`, `wifi_id`) — prevents duplicate assignments.

**Sample Record:**

| mapping_id | user_id | wifi_id | assigned_at |
|---|---|---|---|
| m001-... | u002-... | w001-... | 2026-03-01 10:30:00 |

---

#### Table 5: `detection_events`

| Column | Data Type | Constraint | Description |
|---|---|---|---|
| event_id | BIGINT | PRIMARY KEY, AUTO_INCREMENT | Unique event ID |
| institute_id | VARCHAR(36) | FOREIGN KEY → institutes | Scoping to institute |
| detected_at | DATETIME(6) | NOT NULL | Detection timestamp |
| attack_type | ENUM | NOT NULL | DEAUTH, DISASSOC, UNKNOWN |
| confidence | DECIMAL(5,4) | NOT NULL | Overall confidence (0–1) |
| severity | ENUM | NOT NULL | LOW, MEDIUM, HIGH, CRITICAL |
| layer1_score | SMALLINT | NOT NULL | Heuristic score (0–40) |
| layer2_score | SMALLINT | NOT NULL | ML score (0–100) |
| layer3_score | SMALLINT | NOT NULL | Physical layer score (0–30) |
| total_score | SMALLINT | NOT NULL | Combined weighted score (0–100) |
| attacker_mac | CHAR(17) | NOT NULL | Source MAC of attack frames |
| victim_mac | CHAR(17) | NOT NULL | Target device MAC |
| target_bssid | CHAR(17) | | Targeted access point |
| frame_count | INT | NOT NULL | Frames counted in window |
| attack_duration_ms | INT | NOT NULL | Duration in milliseconds |
| attack_start | DATETIME(6) | NOT NULL | When attack began |
| attack_end | DATETIME(6) | | When attack ended (NULL if ongoing) |

**Sample Record:**

| event_id | severity | attacker_mac | victim_mac | total_score | layer1 | layer2 | layer3 |
|---|---|---|---|---|---|---|---|
| 1 | HIGH | DE:AD:BE:EF:00:01 | 3C:06:30:1A:2B:4F | 78 | 34 | 85 | 22 |

---

## 5.5 Algorithms Used

### 5.5.1 Detection Algorithm (Pseudocode)

```
FUNCTION analyse_packet(frame):
  window = get_recent_frames(last_2_seconds)
  
  // Layer 1
  s1 = weighted_sum(
    rate_analyser(window) * 0.35,
    sequence_validator(window) * 0.25,
    time_anomaly(frame.timestamp) * 0.15,
    session_checker(frame.src) * 0.25
  )
  
  IF s1 < 15: RETURN "NORMAL"
  
  // Layer 2
  features = extract_features(window, frame)
  s2 = ml_api.predict(features).confidence
  
  // Layer 3
  rssi_anomaly = rssi_profiler.check(frame.src, frame.rssi)
  tsf_anomaly = tsf_tracker.check(frame.bssid, frame.tsf)
  s3 = (rssi_anomaly + tsf_anomaly) / 2.0
  
  s_final = max(s1, s2) + min(100, s3 / 2)
  
  RETURN classify(s_final)
```

### 5.5.2 ML Training Process

The machine learning pipeline involves several key steps to ensure robust model performance:

1. **Data Collection and Augmentation:** Initially collected 97 real 802.11 captures using Scapy during a controlled attack simulation. This was augmented to 1,00,000 samples (50,000 attack / 50,000 normal) using Gaussian noise on each feature with σ = 5% and 2% random label flips to simulate noisy real-world conditions.

   ![Figure 5.11 — Dataset overview: 1,00,000 samples, balanced 50/50, 13 features](dataset_overview.png)

   ![Figure 5.12 — Feature value distributions across attack and normal classes](feature_distributions.png)

2. **Preprocessing and Splitting:** Applied `StandardScaler` for feature normalisation. The dataset was then split 80/20 into training and testing sets, using stratification to maintain the balanced class distribution.

   ![Figure 5.13 — Train/test stratified 80/20 split](train_test_split.png)

3. **Model Training and Export:** Trained four distinct models independently. We applied constrained hyperparameters (such as max depth for tree-based models and regularisation for logistic regression) to prevent overfitting. Finally, all four models were serialised using `joblib.dump()` for integration into the real-time Flask API.

### 5.5.3 Prevention Algorithm (Pseudocode)

```
FUNCTION handle_detection(event):
  score = event.final_score
  victim = event.dst_mac
  bssid = event.bssid
  
  kill_chain.update(event.src_mac, score)
  cumulative = kill_chain.get_score(event.src_mac)
  score = max(score, cumulative)
  
  IF score >= 95 OR event.is_spoofed:
    activate_level_4(victim, bssid)
  ELIF score >= 85:
    activate_level_3(bssid)
  ELIF score >= 60:
    activate_level_2()
  ELIF score >= 40:
    activate_level_1(event)
```

---
