# WiFi Deauth Detection & Prevention System - Complete Specification

## DETECTION PIPELINE

```
┌──────────────────────────────────────────────────────────┐
│           PACKET CAPTURE (Monitor Mode)                  │
│              tshark / scapy / libpcap                    │
│           Interface: wlan1 (monitor mode)                │
└────────────────────┬─────────────────────────────────────┘
                     ↓
         ┌───────────────────────┐
         │  Is it deauth frame?  │
         └───────┬───────────────┘
                 ↓ YES
┌────────────────────────────────────────────────────────────┐
│ LAYER 1: FAST FILTER (parallel, 5ms timeout)              │
│                                                            │
│ ├─ RateAnalyzer       → 0/40/70/100 pts                   │
│ │   └─ Counts packets from same MAC in last 10s           │
│ │       ≤ 5  packets  → 0   (Normal)                      │
│ │       ≤ 10 packets  → 40  (Slightly Suspicious)         │
│ │       ≤ 25 packets  → 70  (Suspicious)                  │
│ │       > 25 packets  → 100 (Attack)                      │
│ │                                                          │
│ ├─ SequenceValidator  → score (0–100)                     │
│ │   └─ Checks for duplicate/out-of-order seq numbers      │
│ │                                                          │
│ ├─ TimeAnomalyDetector → score (0–100)                    │
│ │   └─ Detects burst timing anomalies                     │
│ │                                                          │
│ └─ SessionStateChecker → score (0–100)                    │
│     └─ Validates expected client state transitions        │
│                                                            │
│ COMBINED SCORE (weighted):                                 │
│   = Rate(35%) + Seq(25%) + Time(15%) + Session(20%)       │
│   Max = 95 pts                                             │
└────────────────────────┬───────────────────────────────────┘
                         ↓
              ┌──────────────────────┐
              │  Score ≥ 5?          │  ← lowered from 40 (diagram)
              │  AND frame = DEAUTH? │    to catch early bursts faster
              └────┬─────────────────┘
                   │ NO (score 0–4)          │ YES (score ≥ 5)
                   ↓                         ↓
              [BROADCAST               ┌─────────────────────────────────────┐
               MINOR EVENT             │ LAYER 2: ML ENSEMBLE                │
               (LOW severity)]         │                                      │
                                       │ ├─ Decision Tree   → Attack/Normal  │
                                       │ ├─ Random Forest   → Attack/Normal  │
                                       │ ├─ Logistic Reg    → Attack/Normal  │
                                       │ └─ XGBoost         → Attack/Normal  │
                                       │                                      │
                                       │ Majority vote → ML Confidence 0–100%│
                                       └──────────────┬──────────────────────┘
                                                      ↓
                                       ┌──────────────────────────────────────┐
                                       │ LAYER 3: PHYSICAL (always runs)      │
                                       │                                       │
                                       │ ├─ RSSI Sanity Check     → 0–30 pts  │
                                       │ │   missing signal → 20 pts          │
                                       │ │   -50 to -30 dBm → 30 pts (strong) │
                                       │ │   -70 to -50 dBm → 15 pts          │
                                       │ │   < -85 dBm → 0 pts (weak/normal)  │
                                       │ │                                     │
                                       │ ├─ Multi-Client Pattern  → 0–25 pts  │
                                       │ │   (tracks unique targets per MAC    │
                                       │ │    in a 10s rolling window)         │
                                       │ │                                     │
                                       │ └─ Beacon/Broadcast Check → 0–15 pts │
                                       │                                       │
                                       │ Physical Score: 0–70 pts             │
                                       └──────────────┬───────────────────────┘
                                                      ↓
                                       ┌──────────────────────────────────────┐
                                       │ CALCULATE FINAL CONFIDENCE           │
                                       │                                       │
                                       │  normL1 = (L1score / 95)  × 100      │
                                       │  normL2 = ML score (0–100)           │
                                       │  normL3 = (L3score / 70)  × 100      │
                                       │                                       │
                                       │  finalScore = normL1×30%             │
                                       │             + normL2×50%             │
                                       │             + normL3×20%             │
                                       │                                       │
                                       │  safety floor:                        │
                                       │  finalScore = max(finalScore, L1)    │
                                       └──────────────┬───────────────────────┘
                                                      ↓
                                       ┌──────────────────────────────────────┐
                                       │ THREAT LEVEL (from finalScore)       │
                                       │                                       │
                                       │  ≥ 50  → CRITICAL                    │
                                       │  ≥ 30  → HIGH                        │
                                       │  ≥ 15  → MEDIUM                      │
                                       │  < 15  → LOW                         │
                                       └──────────────┬───────────────────────┘
                                                      ↓
                          ┌───────────────────────────────────────────────────┐
                          │ ATTACK TRIGGER DECISION                           │
                          │                                                   │
                          │  mlConfirmsAttack   = ML confidence > 60%        │
                          │                       ← lowered from 75% (diag)  │
                          │  layer1ConfirmsAtk  = finalScore >= 20           │
                          │                       ← lowered from 40% (diag)  │
                          │                                                   │
                          │  if (mlConfirmsAttack OR layer1ConfirmsAttack)   │
                          │      → triggerAttack()   [UNSAFE state]          │
                          │  else                                             │
                          │      → broadcastMinorEvent() [no state change]   │
                          └──────────────┬────────────────────────────────────┘
                                         ↓ UNSAFE triggered
                          ┌──────────────────────────────────────────────────┐
                          │ STATUS FLAGS                                      │
                          │                                                   │
                          │  underAttack = true                               │
                          │  lastAttackTime = now                             │
                          │                                                   │
                          │  Cooldown: 8 seconds after last attack packet     │
                          │  ← reduced from 30s so SAFE flips back quickly   │
                          │                                                   │
                          │  Periodic check: every 2 seconds                 │
                          └──────────────┬────────────────────────────────────┘
                                         ↓
                          ┌──────────────────────────────────────────────────┐
                          │ SSE BROADCAST TO FRONTEND                        │
                          │                                                   │
                          │  Alert fields:                                    │
                          │  ├─ severity  (CRITICAL / HIGH / MEDIUM / LOW)   │
                          │  ├─ attackerMac, targetBssid, targetMac          │
                          │  ├─ score (finalScore)                           │
                          │  ├─ mlConfidence, mlPrediction, modelAgreement   │
                          │  ├─ layer2Score, layer3Score, layer3Notes        │
                          │  └─ timestamp                                    │
                          │                                                   │
                          │  DB: DetectionEvent saved with all sub-scores    │
                          │  DB: updated after ML via updateWithMlScores()   │
                          └──────────────────────────────────────────────────┘
```

---

## PREVENTION LEVELS

### LEVEL 1 (40-60% Confidence) - AUTOMATIC ✅

```
┌─────────────────────────────────────────────┐
│ AUTOMATIC ACTIONS                           │
├─────────────────────────────────────────────┤
│ ✅ Log event to database                   │
│ ✅ Mark attacker as "suspicious"           │
│ ✅ Yellow alert on dashboard                │
│ ✅ Increase monitoring frequency (100ms)    │
│ ✅ Collect packet samples                   │
│ ✅ Build behavioral fingerprint             │
└─────────────────────────────────────────────┘
```

Admin sees: Yellow notification
Admin does: Nothing (just aware)

### LEVEL 2 (60-85% Confidence) - MIXED ⚠️

```
┌─────────────────────────────────────────────┐
│ AUTOMATIC ACTIONS (Happen First)           │
├─────────────────────────────────────────────┤
│ ✅ Temporary block (5 minutes)             │
│ ✅ Add to temp blacklist in database        │
│ ✅ Orange alert on dashboard                │
│ ✅ Try to enable 802.11w PMF (if available) │
│ ✅ Send dashboard notification              │
│ ✅ Email alert to admin                     │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ MANUAL DECISION REQUIRED (Admin Prompt)    │
├─────────────────────────────────────────────┤
│ ⏸️ Modal appears on admin dashboard:       │
│                                             │
│   ┌───────────────────────────────────┐   │
│   │ ⚠️ Action Required                │   │
│   │                                    │   │
│   │ Attacker: AA:BB:CC:DD:EE:FF       │   │
│   │ Confidence: 75%                    │   │
│   │ Currently: TEMP BLOCKED (5 min)   │   │
│   │                                    │   │
│   │ [Make Permanent] [Release Block]  │   │
│   └───────────────────────────────────┘   │
│                                             │
│ 🕐 If admin doesn't respond in 5 minutes:  │
│    ✅ Auto-release block (AUTOMATIC)       │
└─────────────────────────────────────────────┘
```

Summary:
- Block happens automatically ✅
- Admin decides if permanent ⚠️
- Auto-releases if ignored ✅

### LEVEL 3 (85-95% Confidence) - AUTOMATIC ✅

```
┌─────────────────────────────────────────────┐
│ AUTOMATIC ACTIONS (No Approval Needed)     │
├─────────────────────────────────────────────┤
│ ✅ Permanent block attacker MAC             │
│ ✅ Add to permanent blacklist               │
│ ✅ Add iptables DROP rule                   │
│ ✅ Enable 802.11w PMF (mandatory)           │
│ ✅ Configure AP-level frame filtering       │
│ ✅ Enable rate limiting at AP               │
│ ✅ Check for MAC spoofing (fingerprint)     │
│ ✅ Auto-block similar patterns              │
│ ✅ Send critical email                      │
│ ✅ Save packet capture (.pcap)              │
│ ✅ Generate forensic report (PDF)           │
│ ✅ Red critical dashboard alert             │
└─────────────────────────────────────────────┘
```

Admin sees: Critical alert (already handled)
Admin does: Review forensics (optional)
High confidence = System acts immediately

### LEVEL 4 (95%+ Confidence) - CONDITIONAL ⚠️

```
┌─────────────────────────────────────────────┐
│ AUTOMATIC ACTIONS (If Level 4 Enabled)     │
├─────────────────────────────────────────────┤
│ ✅ All Level 3 actions                      │
│ ✅ Channel hopping (if enabled in config)   │
│ ✅ Deploy honeypot                          │
│ ✅ Enable whitelist mode (10 min)           │
│ ✅ Victim fast reconnect priority           │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ MANUAL ENABLE REQUIRED (Counter-Attack)    │
├─────────────────────────────────────────────┤
│ ❌ Counter-attack features OFF by default   │
│                                             │
│ Admin must enable in settings:              │
│   □ Enable Level 4 Active Defense          │
│   □ Enable Counter-Attack Mode             │
│                                             │
│ If enabled, then AUTOMATIC:                 │
│ ✅ Psychological warfare (fake beacons)     │
│ ✅ Deceptive handshake flooding             │
│ ✅ Terminal warning messages                │
│ ✅ Beacon pollution                         │
└─────────────────────────────────────────────┘
```

Summary:
- Defensive actions = Automatic ✅
- Counter-attack = Requires pre-approval ⚠️

---

## 🎛️ ADMIN CONTROL PANEL

What admin can configure:

```
┌──────────────────────────────────────────────┐
│ SYSTEM SETTINGS                              │
├──────────────────────────────────────────────┤
│                                              │
│ AUTOMATIC THRESHOLDS (Adjust sensitivity):   │
│ ─────────────────────────────────────────   │
│ Level 1 Threshold: [40] (0-100)             │
│ Level 2 Threshold: [60] (0-100)             │
│ Level 3 Threshold: [85] (0-100)             │
│ Level 4 Threshold: [95] (0-100)             │
│                                              │
│ AUTOMATIC FEATURES (Toggle on/off):         │
│ ─────────────────────────────────────────   │
│ ☑ Auto-block at Level 2                     │
│ ☑ Auto-block at Level 3                     │
│ ☑ Auto-enable 802.11w PMF                   │
│ ☑ Auto-release temp blocks after timeout    │
│ ☑ Behavioral MAC tracking                   │
│ ☑ RSSI fingerprinting                       │
│                                              │
│ LEVEL 4 FEATURES (Requires approval):       │
│ ─────────────────────────────────────────   │
│ □ Enable Level 4 Active Defense             │
│ □ Enable Counter-Attack Mode                │
│   Legal Mode: [Conservative ▼]              │
│ ☑ Channel Hopping                           │
│ ☑ Honeypot Deployment                       │
│                                              │
│ NOTIFICATIONS (Automatic):                   │
│ ─────────────────────────────────────────   │
│ ☑ Dashboard alerts                          │
│ ☑ Email alerts                              │
│ □ Sound alarm                               │
│                                              │
│ [Save Settings]                              │
└──────────────────────────────────────────────┘
```

---

## 📋 MANUAL ADMIN ACTIONS

Things admin can do at any time:

```
┌──────────────────────────────────────────────┐
│ BLOCKED MACS MANAGEMENT                      │
├──────────────────────────────────────────────┤
│ MAC: AA:BB:CC:DD:EE:FF                       │
│ Type: Temporary (expires in 3 min)           │
│ Confidence: 72%                               │
│                                              │
│ Actions:                                     │
│ [Make Permanent] ← MANUAL                    │
│ [Release Block]  ← MANUAL                    │
│ [View Evidence]  ← MANUAL                    │
└──────────────────────────────────────────────┘

┌──────────────────────────────────────────────┐
│ EVENT REVIEW                                 │
├──────────────────────────────────────────────┤
│ Event #1234                                  │
│ Time: 14:32:05                               │
│ Attacker: AA:BB:CC:DD:EE:FF                  │
│ Confidence: 55% (Level 2 triggered)          │
│ Status: Auto-released after 5 min            │
│                                              │
│ Actions:                                     │
│ [Block Now]      ← MANUAL (retroactive)      │
│ [False Positive] ← MANUAL (whitelist)        │
│ [Download .pcap] ← MANUAL                    │
└──────────────────────────────────────────────┘

┌──────────────────────────────────────────────┐
│ WHITELIST MANAGEMENT                         │
├──────────────────────────────────────────────┤
│ Trusted MAC Addresses:                       │
│                                              │
│ [Add New MAC] ← MANUAL                       │
│ [Import CSV]  ← MANUAL                       │
│                                              │
│ BB:CC:DD:EE:FF:11  [Remove] ← MANUAL         │
│ CC:DD:EE:FF:11:22  [Remove] ← MANUAL         │
└──────────────────────────────────────────────┘

┌──────────────────────────────────────────────┐
│ EMERGENCY CONTROLS                           │
├──────────────────────────────────────────────┤
│ [Clear All History]     ← MANUAL             │
│ [Disable All Blocking]  ← MANUAL             │
│ [Export Forensics]      ← MANUAL             │
│ [System Health Check]   ← MANUAL             │
└──────────────────────────────────────────────┘
```

---

## LEVEL 4: ACTIVE COUNTER-ATTACK (Confidence 95-100% + Admin Enabled)

```
┌─────────────────────────────────────────────────┐
│ 1. Everything from Level 3 PLUS:                │
│                                                  │
│ 2. Deceptive Handshake Flooding                 │
│ - Send FAKE 4-way handshake frames              │
│ - Target: Attacker's MAC address                │
│ - Volume: 1500 frames/second                    │
│ - Duration: 500 seconds                         │
│ - Purpose: Confuse attacker tools               │
│   (Aircrack-ng will get bad data)               │
│                                                  │
│ 3. Honeypot Redirection                         │
│ - Send fake beacon frames                       │
│ - Create illusion of open network               │
│ - SSID: "FREE_WIFI_SECURE"                      │
│ - Attacker wastes time on fake target           │
│                                                  │
│ 4. Rate Limiting (instead of full flood)        │
│ - Don't flood (ethical concern)                 │
│ - Just slow down attacker responses             │
│ - Make attack ineffective without harm          │
└─────────────────────────────────────────────────┘
```

---

## DETECTION FIX: PHYSICAL LAYER FINGERPRINTING

MY DETECTION IS BROKEN SOME ATTACKS GOES IN NORMAL AND NOT PROPER I WANT MAKE PREVENTION PROPER MAC ADDRESS IS GETTING PROPER I WANT OUR METHODS OF LEVEL BUT INSTEAD OF USING ONLY MAC

USING THIS METHOD:

To find the real attacker, you cannot rely on software-based identifiers like MAC addresses, SSIDs, or IP addresses, because attackers easily spoof these to look like legitimate users or Access Points (APs).
Instead, to unmask the physical device of the attacker and effectively counter-attack (such as using Software-Defined Networking to block their specific traffic or physically locating them), modern Intrusion Detection Systems (IDS) use Physical Layer (PHY) characteristics and Hardware Fingerprinting.

Here are the specific parameters you can use:

### 1. Received Signal Strength Indicator (RSSI)

You have:     wlan1 (monitor mode) ✅
              wlan0 (broken)       ❌

Trilateration needs:  3 sensors   ❌ NOT POSSIBLE

#### RSSI Signature Matching (1 Sensor, Very Effective)

CONCEPT:
Build RSSI "fingerprint" of every device you have seen
When attack starts: compare attack frame RSSI to all known devices

If attack RSSI matches a known client → attacker spoofing that client
If attack RSSI matches nothing → new unknown device = suspicious
If attack RSSI matches known AP but frame is deauth → AP impersonation

```python
class RSSISignatureMatcher:
    """
    Matches RSSI to known device signatures.
    Detects: AP impersonation, client spoofing.
    Works with single sensor.
    """

    def __init__(self, tolerance_db=8):
        self.signatures  = {}     # mac → rssi_signature
        self.tolerance   = tolerance_db

    def learn_device(self, mac, rssi_list):
        """
        Learn the RSSI signature of a legitimate device.
        Call this during normal operation (before attacks).
        """
        self.signatures[mac] = {
            'mean':  statistics.mean(rssi_list),
            'std':   statistics.stdev(rssi_list) if len(rssi_list) > 1 else 0,
            'min':   min(rssi_list),
            'max':   max(rssi_list),
            'count': len(rssi_list)
        }

    def check_frame(self, claimed_mac, observed_rssi):
        """
        Frame claims to be from claimed_mac.
        Does the RSSI match what we know about that MAC?

        Returns:
            'match'    → RSSI consistent with known device
            'mismatch' → RSSI very different → possible spoofing
            'unknown'  → never seen this MAC before
        """
        if claimed_mac not in self.signatures:
            return 'unknown', 0

        sig      = self.signatures[claimed_mac]
        expected = sig['mean']
        deviation = abs(observed_rssi - expected)

        if deviation <= self.tolerance:
            return 'match', deviation
        else:
            return 'mismatch', deviation   # Likely spoofed frame

    def mismatch_score(self, claimed_mac, observed_rssi):
        """Returns 0-20 score. Higher = more likely spoofed."""
        result, deviation = self.check_frame(claimed_mac, observed_rssi)

        if result == 'unknown':
            return 10
        elif result == 'mismatch':
            if deviation > 25:
                return 20
            elif deviation > 15:
                return 15
            else:
                return 8
        else:
            return 0    # Match = legitimate
```

### 2. Angle of Arrival (AoA)
- **How it works**: AoA measures the exact directional angle from which the radio frequency waves are hitting the receiving antenna.
- **Finding & Counter-Attacking**: By utilizing AoA localization algorithms, your system can ascertain the exact physical direction of the spoofed attack frames. Once the direction is known, you can configure your network to actively block or drop all traffic originating from that specific physical angle, neutralizing the attacker regardless of what MAC address they use.

### 3. Hardware Clock Skew
- **How it works**: Every Wi-Fi network interface card contains a hardware crystal oscillator that regulates its internal clock. Due to microscopic manufacturing imperfections, every card has a slightly different time drift, known as "clock skew".
- **Finding the Attacker**: You can extract the timestamp data from the MAC layer frames. Because clock skew is a unique hardware property that is incredibly difficult for an attacker to fake in software, it acts as a permanent fingerprint. If a device claiming to be your AP suddenly exhibits a different clock skew, you have positively identified the attacker's hardware.

### 4. Channel State Information (CSI)
- **How it works**: CSI provides highly detailed, fine-grained information about how a wireless signal propagates through the air, including how it reflects and bounces off walls and objects (multipath fading).
- **Finding the Attacker**: CSI extracts the physical layer phase errors and spatial location of the transmitter. Because the attacker is transmitting from a different location than the legitimate AP or client, their CSI "signature" will be distinctly different, allowing you to flag the exact physical transmitter responsible for the rogue traffic.

### 5. Frame Inter-Arrival Time (IAT)
- **How it works**: IAT measures the microscopic time intervals between two consecutively received frames.
- **Finding the Attacker**: Attackers utilizing tools to inject deauthentication floods or relay traffic via an Evil Twin naturally introduce processing delays or transmission anomalies. By analyzing the temporal characteristics and timing disparities (using the Radiotap header), you can fingerprint the attacker based on the behavioral timing of their specific device or attack script.

---

## VICTIM FAST RECONNECT PRIORITY (Level 4)

How to make user of wifi stay connected in WiFi during deauth attacks in wpa2 and old device?

Yes, it is possible to keep users connected on WPA2 and older legacy devices during a deauthentication attack. Because older devices lack support for the official IEEE 802.11w Protected Management Frames (PMF) standard, defenders must use software-based techniques that alter how the Access Point (AP) or network processes incoming deauthentication requests.

By preventing the AP from executing the spoofed frames, the connection is never broken. Here are the primary methods used to achieve this:

### 1. Execution Delay (Temporal State Recovery)
This is a software modification that changes how the AP reacts to a deauthentication frame. Instead of disconnecting the user immediately, the system delays the effect of the management frame for a brief window (e.g., 500 milliseconds to 10 seconds).
- **How it works**: The AP waits to see what the client does next. Because a legitimate client that sends a deauthentication frame will stop sending data, receiving data frames after a deauthentication request is highly anomalous.
- **The Result**: If the AP receives subsequent normal data frames from the client during this delay window, it assumes the prior deauthentication frame was spoofed by an attacker, drops the frame, and allows the client to stay connected.

### 2. Active Frame Dropping via SDN or WIPS
Wireless Intrusion Prevention Systems (WIPS) or Software-Defined Networking (SDN) controllers can be integrated into the network to intercept traffic before the AP processes it.
- **How it works**: The system continuously monitors network traffic for attack signatures, such as a sudden flood of deauthentication frames or MAC address spoofing anomalies.
- **The Result**: When the system identifies a deauthentication frame as malicious, it triggers a Drop_action(). The system silently discards the malicious packets and refuses to acknowledge them, which mitigates the immediate threat and maintains the seamless operation of the connected devices.

### 3. Firmware-Level Token Verification
If you have the ability to apply a lightweight firmware update to the AP and legacy clients, you can implement custom authentication for management frames without needing the hardware upgrades required for WPA3.
- **UUID Hashing**: During the initial connection, the client and AP randomly generate and exchange hashed Universally Unique Identifiers (UUIDs). Whenever a deauthentication frame is sent, it must contain the original token. If an attacker sends a spoofed frame without the exact token, the AP rejects the request and keeps the client connected.
- **Letter-Envelope Protocol**: Similar to UUIDs, the client and AP generate and share large prime numbers upon connecting. A legitimate disconnection requires sending a specific prime factor. If the attacker's frame does not contain the mathematically correct factor, the frame is ignored and the connection remains intact.

---

## SAMPLE CODING REFERENCE

Use `/home/supreeth/Desktop/honeypot.py` for sample coding patterns (raw socket beacon frame injection, monitor mode setup, frame construction).

---

## DEVELOPMENT PROCESS

After completing each bigger process, stop and tell the things to test before proceeding.
