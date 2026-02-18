# Real-Time Deauth Detection Mode Enabled

You requested a fully real-time system with no mock or dummy data using `wlan1`.

## Changes Made
1. **Mock Data Removed:** The fallback to mock client data in `WiFiScannerService.java` has been removed. All data shown in "Connected Clients" now comes directly from live scans on `wlan1`.
2. **Interface Configuration:** The system is explicitly configured to use `wlan1` for packet monitoring and client scanning.
3. **Startup Script:** Created `start_realtime_system.sh` to launch the entire stack (Backend, Frontend, Packet Capture Engine) with the correct real-time configuration.

## Pre-requisites
- **Interface:** `wlan1` must be available (checking `iwconfig`, it is present and in Monitor mode).
- **Root Privileges:** Packet capture requires `sudo`. The script will ask for your password.

## How to Run
1. **Setup Dependencies (First Time Only):**
   ```bash
   ./setup_environment.sh
   ```

2. **Start the System:**
   ```bash
   ./start_realtime_system.sh
   ```
   This script will:
   - Stop any existing processes.
   - Start the Backend (API).
   - Start the Frontend (Dashboard).
   - Start the Real-time Packet Capture Engine on `wlan1`.

3. **Access Dashboard:**
   - Go to [http://localhost:3000](http://localhost:3000)
   - Login as `test@test.com` / `Test12345` (or register a new admin).
   - **Real-Time Detection:** The dashboard will now show *only* real detection events captured from `wlan1`.
   - **Connected Clients:** Clicking "Connected Clients" will run a live scan using `airodump-ng` on `wlan1`. Please wait ~15 seconds for results.

## Troubleshooting
- **No Clients Found?** Ensure devices are actively transmitting near the antenna. Since we removed mock data, if no clients are found, the list will be empty.
- **Permission Denied?** Ensure you provide the sudo password when prompted by the startup script.
