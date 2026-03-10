# Comprehensive Explanation of the WiFi Security System

This document provides a deep dive into the architecture, components, and data flow of the WiFi Deauthentication Detection System.

## 1. High-Level Architecture

The system is built as a distributed application with three main components working in parallel:

1.  **Packet Capture Engine (The "Eyes")**:
    *   Written in **Python**.
    *   Uses **Scapy** and **Airodump-ng**.
    *   Listens to raw WiFi frames (Layer 2) from the monitor interface (e.g., `wlan1`).
    *   Filters specifically for Management Frames (Type 0), focusing on Deauthentication (Subtype 12) and Disassociation (Subtype 10) frames.
    *   Forwards captured packet metadata to the Backend via HTTP REST API.

2.  **Backend Core (The "Brain")**:
    *   Written in **Java (Spring Boot 3)**.
    *   Processes incoming packet data in real-time.
    *   Runs **Layer 1 Analyzers** (Statistical/Heuristic detection).
    *   Runs **Layer 2 Analyzers** (Machine Learning models - XGBoost/RandomForest).
    *   Manages the database (MySQL) via Hibernate/JPA.
    *   Exposes a REST API for the Frontend to fetch data and control the system.

3.  **Frontend Dashboard (The "Face")**:
    *   Written in **React (TypeScript)**.
    *   Provides a responsive UI for administrators.
    *   Displays real-time alerts, network graphs, and attack history.
    *   Allows configuration of improved security settings and managing detection thresholds.

---

## 2. Detailed Component Breakdown

### A. The Packet Sniffer (`packet-capture/`)
This module is the entry point for all data. It puts the WiFi card into **Monitor Mode**, allowing it to see all traffic in the air, not just traffic destined for your computer.

*   **`sniffer.py`**: The main script. It uses `scapy.sniff` to capture packets.
    *   **Filtering**: It immediately discards data packets (like Netflix/YouTube traffic) to save performance. It only cares about management frames.
    *   **Parsing**: Extracts Source MAC, Destination MAC, BSSID (Access Point MAC), Sequence Number, and RSSI (Signal Strength).
    *   **Forwarding**: Batches these packets and sends them to `http://localhost:8080/api/packets/deauth/batch`.
*   **`scan_networks.py`**: A wrapper around the `airodump-ng` tool. It scans for available networks (SSIDs) in the area to populate the "Networks" list in the dashboard.
*   **`scan_clients.py`**: Scans for devices connected to a specific network to populate the "Connected Clients" list.

### B. The Backend (`wifi-security-backend/`)
This is a standard specialized Spring Boot application.

*   **Controllers (`com.wifi.security.controller`)**:
    *   `PacketController`: Receives the raw data from Python.
    *   `AlertController`: Sends alerts to the frontend (often via Server-Sent Events or Polling).
    *   `ScanController`: Triggers the Python scanning scripts and returns the results.
*   **Services (`com.wifi.security.service`)**:
    *   **`Layer1Service`**: The first line of defense. It uses heuristics:
        *   *Rate Analysis*: "Are we seeing too many deauth frames in 5 seconds?"
        *   *Sequence Analysis*: "Are the packet sequence numbers jumping strangely?"
    *   **`WiFiScannerService`**: Manages the execution of the Python scripts (`scan_networks.py`) using Java's `ProcessBuilder`.
*   **Database (`MySQL`)**:
    *   Stores `CapturedPacket` (raw history).
    *   Stores `DetectionEvent` (alerts when an attack is found).
    *   Stores `Institute` and `User` data for login/authentication.

### C. The Frontend (`wifi-security-frontend/`)
A React Single Page Application (SPA).

*   **Pages**:
    *   **`Login.tsx` / `Register.tsx`**: Entry points. Uses JWT (JSON Web Tokens) for security.
    *   **`AdminDashboard.tsx`**: The main command center.
        *   *Network List*: Shows nearby WiFi networks (from `scan_networks.py`).
        *   *Connected Clients*: Shows users on a network (from `scan_clients.py`).
        *   *Recent Deauths*: A live table of attack packets.
    *   **`DetectionMonitor.tsx`**: A dedicated view for watching attacks unfold in real-time.
*   **Live Updates**: The dashboard polls the backend every few seconds (e.g., `setInterval` in `DetectionFeed.tsx`) to fetch the latest alerts without refreshing the page.

---

## 3. The Lifecycle of a Deauth Attack Detection

1.  **Attack Starts**: An attacker sends a flood of "Deauthentication" frames to kick a victim off their WiFi.
2.  **Capture**: `sniffer.py` sees these frames flying through the air.
3.  **Forward**: `sniffer.py` sends a JSON batch of these frames to the Java Backend.
4.  **Analysis**:
    *   The `PacketController` receives data.
    *   `Layer1Service` sees 50 frames in 1 second (Threshold exceeded!).
    *   It flags this as a **CRITICAL** threat.
5.  **Storage**: The detected event is saved to the `detection_events` table in MySQL.
6.  **Alert**: The React Frontend polls the backend, sees the new event, and displays a red alert banner saying "Deauth Attack Detected!".

---

## 4. How to Build and Run

### Prerequisites
*   Java JDK 17+
*   Node.js & npm
*   Python 3.10+ (with `scapy`, `requests`)
*   MySQL Database (Running locally or via Aiven)
*   WiFi Adapter supporting Monitor Mode

### Step 1: Start the Database & Backend
```bash
# In /wifi-security-backend
./mvnw clean compile  # Compiles the Java code
./mvnw spring-boot:run # Starts the web server on port 8080
```

### Step 2: Start the Frontend
```bash
# In /wifi-security-frontend
npm install  # Downloads React dependencies
npm start    # Starts the UI server on port 3000
```
*Access the UI at `http://localhost:3000`*

### Step 3: Start the Sniffer (Requires Root)
```bash
# In /packet-capture
# First, enable monitor mode (e.g., airmon-ng start wlan0)
sudo python3 sniffer.py --interface wlan1
```

---

## 5. Security Features Implemented
*   **JWT Authentication**: Ensures only authorized admins can see the dashboard.
*   **BCrypt Hashing**: Passwords are never stored in plain text.
*   **Role-Based Access**: Admins have full control; Viewers can only watch.
