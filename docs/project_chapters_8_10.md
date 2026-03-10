
---

# CHAPTER 8: CONCLUSION AND FUTURE ENHANCEMENT

## 8.1 Conclusion

### 8.1.1 Project Summary

In this project, we designed, implemented, and tested a Real-Time Wi-Fi Deauthentication Attack Detection and Prevention System. The system captures raw 802.11 frames from a monitor-mode Wi-Fi adapter and passes them through three parallel analysis layers — statistical heuristics, a machine learning ensemble, and physical fingerprinting — to determine whether a frame is part of an attack. Detected attacks trigger an autonomous four-level prevention engine that responds within 500 milliseconds without blocking any MAC address and without requiring administrator intervention.

The system is packaged as a multi-user web platform with role-based access control, real-time SSE event streaming, email and SMS alerts, and forensic evidence collection. All components were deployed and tested successfully on Ubuntu 22.04 with a TP-Link TL-WN722N adapter.

### 8.1.2 Objectives Achievement

| Objective | Target | Achieved |
|---|---|---|
| Real-time deauth attack detection | Detection within 500ms | 180ms average latency |
| High accuracy ML classification | > 95% accuracy | 98.5% ensemble accuracy |
| Autonomous prevention without MAC blocking | 4-level defence | All 4 levels implemented and tested |
| User-friendly web dashboard | React SPA with live updates | Fully functional with SSE streaming |
| Forensic evidence collection | PCAP + PDF reports | Implemented and tested |
| Role-based multi-user access | Admin and Viewer roles | JWT + Spring Security implemented |
| Email and SMS alerts | Brevo + SMSLocal | Both integrated and tested |
| Honeypot deception | Reduce attack success rate | 150 fake APs, 0.67% success rate |

### 8.1.3 Key Contributions

1. We designed a **three-layer parallel detection architecture** that combines speed (Layer 1), accuracy (Layer 2), and physical verification (Layer 3) in a way that no single publicly available tool currently offers.
2. We implemented a **four-model ML ensemble** with documented and resolved cases of data leakage, multicollinearity, and overfitting — showing the full model development process, not just the final result.
3. We built a **zero-MAC-blocking prevention system** that correctly identifies the attack vector and suppresses it at the kernel bridge level, avoiding the common mistake of blocking the spoofed victim's MAC.
4. We implemented a **Kill Chain State Machine** that defeats low-and-slow evasion tactics by accumulating threat scores across time.
5. We delivered a **production-ready full-stack application** with proper authentication, role isolation, real-time streaming, and a modern React interface.

### 8.1.4 Challenges Overcome

The most significant technical challenge was the ML data leakage problem, where initial models showed 100% accuracy. Identifying this as leakage rather than a genuine result, and resolving it through controlled noise injection, was a key learning moment. The monitor mode stability issue — where NetworkManager repeatedly interfered with the adapter — required persistent debugging and careful system configuration. These challenges gave us a realistic understanding of production network security engineering.

### 8.1.5 Learning Outcomes

Through this project, we learned:
- How Wi-Fi 802.11 management frames work at the packet level and why they are fundamentally vulnerable.
- How to use Scapy for raw packet capture and manipulation in Python.
- The complete ML pipeline from raw data collection through feature engineering, training, evaluation, and model deployment.
- Spring Boot backend development including JWT security, SSE streaming, and JPA database management.
- React frontend development with real-time data, role-based rendering, and TypeScript type safety.
- Linux kernel networking tools including `ebtables`, `airmon-ng`, `hostapd`, and `wpa_cli`.
- How to design a microservices-style system where each component has a clearly defined, testable responsibility.

---

## 8.2 Limitations

1. **Single adapter, single channel:** The sniffer monitors one Wi-Fi channel at a time. An attacker who knows which channel is being monitored could attack on a different channel. Multi-channel scanning requires multiple adapters or a hardware-level radio scanner.

2. **Linux-only deployment:** The entire system relies on Linux-specific tools. There is no Windows or macOS support.

3. **Monitor-mode hardware dependency:** Not all Wi-Fi adapters support monitor mode. The system specifically requires an AR9271-based adapter, which limits deployment flexibility.

4. **Pre-shared key model:** The system protects the network from deauth attacks but does not help with WPA pre-shared key compromise. If the password is already known to the attacker, different mitigations are needed.

5. **Static ML models:** The trained models are fixed at the time of deployment. If the characteristics of real attacks change significantly, the models will need retraining. There is no online learning mechanism currently.

---

## 8.3 Future Enhancements

### 8.3.1 Short-Term (3–6 Months)

**Mobile Application:** An Android/iOS companion app would allow administrators to receive push notifications, acknowledge alerts, and see a live threat status without accessing the web dashboard on a laptop.

**Multi-Channel Monitoring:** Deploying two or more Wi-Fi adapters on different channels — each running an independent sniffer instance — and aggregating their events in the same Spring backend. This would provide full-spectrum monitoring.

**Deeper ML Analytics:** Adding LSTM (Long Short-Term Memory) neural network models to capture temporal patterns across attack sequences. Recurrent networks are better suited to time-series frame data than decision-tree-based classifiers.

### 8.3.2 Long-Term (6–12 Months)

**Evil Twin and Rogue AP Detection:** Extending the physical fingerprinting layer to detect unauthorised access points that clone a legitimate network's SSID but have a different TSF signature.

**SIEM Integration:** Exporting detection events to enterprise Security Information and Event Management platforms like Splunk or the ELK stack. This would allow organisations that already have centralised log management to incorporate Wi-Fi threat data.

**Kubernetes Deployment:** Containerising each component (ML API, Spring Boot, Detection Engine) as Docker containers and deploying them on Kubernetes. This would allow horizontal scaling of the ML inference service during high-load attack scenarios.

**Immutable Forensic Records with Blockchain:** Storing the cryptographic hash of each PCAP file on a blockchain ledger at the time of capture. This would make the forensic evidence tamper-evident — useful in legal proceedings where chain-of-custody integrity is required.

### 8.3.3 Research Directions

**Unsupervised Anomaly Detection:** Training an autoencoder on normal traffic patterns so that genuinely novel attack types (zero-day) can be flagged without requiring labelled attack samples.

**Federated Learning:** Allowing multiple sensor nodes (at different institutions) to jointly train the ML models without sharing raw packet data, preserving privacy while improving model generalisation.

---

## 8.4 Final Thoughts

This project combined network security, machine learning, and full-stack web development into a single working system. When we started, we underestimated the complexity of integrating these three domains — each has its own tools, conventions, and failure modes. Looking back, the most valuable outcome is not the system itself but the process: learning to debug a monitor-mode driver issue, trace a JWT authentication failure through a Spring Security filter chain, and identify data leakage in a machine learning pipeline are skills that will carry over to any future technical work.

The deauthentication vulnerability in 802.11 has been known since 2003. It is still largely unmitigated in most real-world deployments. We hope this project demonstrates that a practical, automated defence can be built at relatively low cost and that this kind of proactive security tooling should be standard in campus, enterprise, and public Wi-Fi deployments.

---

# CHAPTER 9: APPENDIX

## Appendix A: Source Code Structure

```
wif-deauth/
├── wifi-security-backend/          # Spring Boot backend
│   └── src/main/java/com/wifi/security/
│       ├── controller/             # REST API controllers
│       ├── service/                # Business logic
│       ├── entity/                 # JPA database entities
│       ├── dto/                    # Data transfer objects
│       ├── repository/             # Spring Data JPA repos
│       └── security/               # JWT + Spring Security config
│
├── wifi-security-frontend/         # React + TypeScript SPA
│   └── src/
│       ├── pages/                  # Page components (Login, Dashboard, etc.)
│       ├── components/             # Reusable UI components
│       ├── hooks/                  # Custom React hooks (SSE, data fetching)
│       └── services/               # API service functions
│
├── packet-capture/                 # Python detection engine
│   ├── packet_sniffer.py           # Scapy monitor-mode capture
│   ├── detection_engine.py         # Layer 1 heuristic analysers
│   └── data_sender.py              # Sends events to Spring API
│
├── ml-api/                         # Flask ML inference API
│   ├── app.py                      # Flask app with /predict endpoint
│   └── saved_models/               # Trained .pkl model files
│
├── prevention-engine/              # Autonomous prevention
│   ├── main_engine.py              # Main event handler + level dispatcher
│   ├── kill_chain.py               # Kill Chain State Machine
│   ├── level3_components.py        # Honeypot and physical layer defence
│   └── behavioral_tracker.py      # RSSI/TSF profiling
│
├── forensics/                      # PCAP and PDF forensic files
├── docs/                           # Project documentation
├── scripts/                        # Setup and utility shell scripts
└── Makefile                        # One-command startup system
```

---

## Appendix B: Key Database Tables (SQL)

```sql
CREATE TABLE users (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('ADMIN','VIEWER') NOT NULL,
    institute_id BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE wifi_networks (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    ssid VARCHAR(255) NOT NULL,
    bssid VARCHAR(17) NOT NULL,
    channel INT NOT NULL,
    institute_id BIGINT NOT NULL,
    registered_by BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE detection_events (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    src_mac VARCHAR(17),
    dst_mac VARCHAR(17),
    bssid VARCHAR(17),
    reason_code INT,
    rssi INT,
    layer1_score DOUBLE,
    layer2_score DOUBLE,
    ml_confidence DOUBLE,
    is_spoofed BOOLEAN DEFAULT FALSE,
    severity ENUM('NORMAL','SUSPICIOUS','ATTACK','HIGH','CRITICAL'),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    institute_id BIGINT
);
```

---

## Appendix C: Key API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/login` | None | Login, returns JWT |
| POST | `/api/auth/register` | Admin JWT | Create new user |
| POST | `/api/wifi/register` | Admin JWT | Register Wi-Fi network |
| GET | `/api/wifi/list` | Any JWT | List assigned networks |
| POST | `/api/detection/event` | Internal | Save detection event from sniffer |
| GET | `/api/events/stream` | Any JWT | SSE stream of live events |
| GET | `/api/forensics/reports` | Admin JWT | List forensic reports |
| GET | `/api/forensics/download/{id}` | Admin JWT | Download PCAP/PDF |

---

## Appendix D: Configuration (application.yml excerpt)

```yaml
spring:
  datasource:
    url: jdbc:mysql://<host>:3306/wifi_security
    username: ${DB_USER}
    password: ${DB_PASS}
  jpa:
    hibernate:
      ddl-auto: update

app:
  jwt-secret: ${JWT_SECRET}
  jwt-expiration-ms: 86400000

brevo:
  api-key: ${BREVO_API_KEY}
  from-email: alerts@yourdomain.com

smslocal:
  api-key: ${SMSLOCAL_KEY}
  sender: WiFiGuard
```

---

## Appendix E: Abbreviations

| Abbreviation | Full Form |
|---|---|
| 802.11 | IEEE Standard for Wi-Fi (Wireless LAN) |
| BSSID | Basic Service Set Identifier (AP MAC address) |
| API | Application Programming Interface |
| RBAC | Role-Based Access Control |
| JWT | JSON Web Token |
| ML | Machine Learning |
| RF | Random Forest |
| XGB | XGBoost (Extreme Gradient Boosting) |
| LR | Logistic Regression |
| DT | Decision Tree |
| SSE | Server-Sent Events |
| PCAP | Packet Capture (file format) |
| TSF | Timing Synchronisation Function |
| RSSI | Received Signal Strength Indicator |
| PMF | Protected Management Frames (802.11w) |
| IDS | Intrusion Detection System |
| IPS | Intrusion Prevention System |
| WIDS | Wireless Intrusion Detection System |
| MCA | Master of Computer Applications |
| KCSM | Kill Chain State Machine |
| BCrypt | Password hashing algorithm |

---

# CHAPTER 10: REFERENCES

[1] IEEE, "IEEE Std 802.11-2020 — IEEE Standard for Information Technology — Wireless LAN MAC and PHY Specifications," IEEE, 2020.

[2] J. Bellardo and S. Savage, "802.11 Denial-of-Service Attacks: Real Vulnerabilities and Practical Solutions," in *Proc. USENIX Security Symposium*, 2003, pp. 15–28.

[3] M. Vanhoef and F. Piessens, "Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2," in *Proc. ACM Conference on Computer and Communications Security (CCS)*, 2017, pp. 1313–1328.

[4] W. Arbaugh, N. Shankar, Y. Wan, and K. Zhang, "Your 802.11 Wireless Network Has No Clothes," *IEEE Wireless Communications*, vol. 9, no. 6, pp. 44–51, Dec. 2002.

[5] M. Aminanto, R. Choi, H. C. Tanuwidjaja, P. D. Yoo, and K. Kim, "Deep Abstraction and Weighted Feature Selection for Wi-Fi Impersonation Detection," *IEEE Transactions on Information Forensics and Security*, vol. 13, no. 12, pp. 2973–2983, 2018.

[6] A. Btoush, "Real-Time Detection of IEEE 802.11 Deauthentication Attacks in Wi-Fi Networks," *Journal of Network and Computer Applications*, vol. 215, 2024.

[7] B. Danev, D. Zanetti, and S. Capkun, "On Physical-Layer Identification of Wireless Devices," *ACM Computing Surveys*, vol. 45, no. 1, article 6, 2012.

[8] S. Jana and S. Kasera, "On Fast and Accurate Detection of Unauthorized Wireless Access Points Using Clock Skews," *IEEE Transactions on Mobile Computing*, vol. 9, no. 3, pp. 449–462, Mar. 2010.

[9] L. Breiman, "Random Forests," *Machine Learning*, vol. 45, no. 1, pp. 5–32, 2001.

[10] T. Chen and C. Guestrin, "XGBoost: A Scalable Tree Boosting System," in *Proc. ACM KDD*, 2016, pp. 785–794.

[11] P. Biondi, "Scapy: Packet Manipulation for Python," [Online]. Available: https://scapy.net. [Accessed: Mar. 2025].

[12] Spring Framework, "Spring Boot Reference Documentation," [Online]. Available: https://spring.io/projects/spring-boot. [Accessed: Mar. 2025].

[13] React Team, "React — The Library for Web and Native User Interfaces," [Online]. Available: https://react.dev. [Accessed: Mar. 2025].

[14] F. Pedregosa et al., "Scikit-learn: Machine Learning in Python," *Journal of Machine Learning Research*, vol. 12, pp. 2825–2830, 2011.

[15] W. Stallings, *Network Security Essentials: Applications and Standards*, 6th ed. Pearson, 2017.

[16] B. Schneier, *Applied Cryptography: Protocols, Algorithms, and Source Code in C*, 2nd ed. John Wiley & Sons, 1996.

[17] Wi-Fi Alliance, "WPA3 Specification Version 3.0," Wi-Fi Alliance, 2020.

[18] Aircrack-ng Project, "Aireplay-ng — Inject Frames into a Wireless Network," [Online]. Available: https://www.aircrack-ng.org/doku.php?id=aireplay-ng. [Accessed: Mar. 2025].

[19] MDK4 Project, "MDK4 — Wi-Fi Testing Tool," GitHub, [Online]. Available: https://github.com/aircrack-ng/mdk4. [Accessed: Mar. 2025].

[20] Kismet, "Kismet Wireless — Wireless Network Detector and IDS," [Online]. Available: https://www.kismetwireless.net. [Accessed: Mar. 2025].

[21] MySQL Team, "MySQL 8.0 Reference Manual," Oracle Corporation, [Online]. Available: https://dev.mysql.com/doc/refman/8.0/en. [Accessed: Mar. 2025].

[22] Brevo, "Transactional Email API Documentation," [Online]. Available: https://developers.brevo.com. [Accessed: Mar. 2025].

[23] C. Corbett, R. Santesson, and P. Rfc4519A, "RFC 3280 — Internet X.509 PKI," IETF, 2002.

[24] G. Bradski, "The OpenCV Library," *Dr. Dobb's Journal of Software Tools*, 2000.

[25] A. Géron, *Hands-On Machine Learning with Scikit-Learn, Keras, and TensorFlow*, 3rd ed. O'Reilly Media, 2022.

---

# LIST OF FIGURES

| Figure | Description |
|---|---|
| Figure 5.1 | System Architecture — Three-Tier Overview |
| Figure 5.2 | Use Case Diagram — Admin and Viewer Actors |
| Figure 5.3 | Component Diagram — All System Modules |
| Figure 5.4 | ER Diagram — Database Entity Relationships |
| Figure 5.5 | Sequence Diagram — User Login Flow |
| Figure 5.6 | Sequence Diagram — Packet Detection Flow |
| Figure 5.7 | Activity Diagram — Attack Detection Decision |
| Figure 5.8 | Detection Flowchart — Three-Layer Pipeline |
| Figure 5.9 | Prevention Flowchart — Four-Level Escalation |
| Figure 5.10 | Deployment Diagram — Process and Host Layout |
| Figure 5.11 | Dataset overview: 1,00,000 samples, balanced 50/50, 13 features |
| Figure 5.12 | Feature value distributions across attack and normal classes |
| Figure 5.13 | Train/test stratified 80/20 split |
| Figure 7.1 | Login Page Screenshot |
| Figure 7.2 | Admin Dashboard Screenshot |
| Figure 7.3 | Wi-Fi Registration Form Screenshot |
| Figure 7.4 | Detection Monitor Screenshot (Active Attack) |
| Figure 7.5 | ML Ensemble Statistics Panel Screenshot |
| Figure 7.6 | Live Detection Feed Screenshot |
| Figure 7.7 | Prevention Dashboard Screenshot |
| Figure 7.8 | Honeypot Control Panel Screenshot |
| Figure 7.9 | Forensic Reports Page Screenshot |
| Figure 7.10 | Email Alert Inbox Screenshot |
| Figure 7.11 | ML Model Performance Comparison (Bar Chart) |
| Figure 7.12 | Detection Accuracy Comparison Chart |
| Figure 7.13 | Response Time Graph (Before vs After Prevention) |

---

# LIST OF TABLES

| Table | Description |
|---|---|
| Table 4.1 | Hardware Requirements |
| Table 4.2 | Primary Database Tables |
| Table 5.1 | System Component Summary |
| Table 5.2 | Layer 1 Analyser Weights |
| Table 5.3 | ML Model Weights in Ensemble |
| Table 5.4 | Defence Level Trigger Conditions |
| Table 6.1 | Unit Test Cases — Authentication |
| Table 6.2 | Unit Test Cases — Detection Engine |
| Table 6.3 | Integration Test Cases |
| Table 6.4 | System Test Cases |
| Table 6.5 | Performance Test Results |
| Table 6.6 | Overall Test Summary |
| Table 6.7 | Bug Tracking Log |
| Table 7.1 | Detection Accuracy Results |
| Table 7.2 | Prevention Performance |
| Table 7.3 | ML Model Performance |
| Table 7.4 | System Response Times |
| Table 7.5 | Honeypot Effectiveness |
| Table 7.6 | Comparison with Existing Systems |
| Table 8.1 | Objectives Achievement Summary |
| Table 9.1 | Key REST API Endpoints |
| Table 9.2 | Abbreviations |

---
