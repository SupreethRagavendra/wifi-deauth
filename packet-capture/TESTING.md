# Test Plan - Module 2

## 1. Monitor Mode Verification
**Objective:** Ensure the script can toggle the wireless interface to monitor mode.

**Steps:**
1. Identify your wireless interface: `ip link` or `iw dev`.
2. Edit `.env` and set `WIFI_INTERFACE` to your interface (e.g., `wlan0`).
3. Run the script: `sudo python3 main.py`.
4. Observe output:
   - "Enabling monitor mode on wlan0..."
   - "✓ Monitor mode enabled"
5. Open another terminal and run `iwconfig`.
   - **Expected:** Interface State should say `Mode:Monitor`.
6. Press `Ctrl+C` to stop the script.
   - **Expected:** "✓ Monitor mode disabled" and `iwconfig` shows `Mode:Managed`.

## 2. Packet Capture Verification
**Objective:** Verify that deauth frames are detected and parsed.

**Prerequisites:**
- A secondary device (smartphone/laptop) connected to a Wi-Fi network.
- `aircrack-ng` suite installed (`sudo apt install aircrack-ng`).

**Steps:**
1. Start the capture engine: `sudo python3 main.py`.
2. In a separate terminal, launch a deauth attack against your own test device (DO NOT use on unauthorized networks):
   ```bash
   # Get BSSID of your router
   sudo airodump-ng wlan0
   
   # Send 5 deauth packets
   sudo aireplay-ng --deauth 5 -a <ROUTER_BSSID> wlan0
   ```
3. Observe the capture engine output.
   - **Expected:**
     ```
     Deauth: <ROUTER_MAC> → <BROADCAST_OR_DEVICE> (RSSI: -XX dBm, Seq Gap: 0)
     ```
   - If `Seq Gap` increases, it means packets received are in sequence.

## 3. Backend Communication Verification
**Objective:** Ensure packets are sent to the Java backend.

**Prerequisites:**
- Java backend running on `http://localhost:8080`.

**Steps:**
1. Ensure `Config.BUFFER_SIZE` is small (e.g., 5) for easier testing, or wait 5 seconds.
2. Generate deauth packets as above.
3. Observe output:
   - **Expected:** `✓ Sent X packets to backend` (Green text).
4. Check Java backend logs.
   - **Expected:** Logs showing received packet batch.

**Failure Case Testing:**
1. Stop the Java backend.
2. Generate packets.
3. Observe output:
   - **Expected:** `✗ Attempt 1/3 failed: ...Connection refused...`
   - **Expected:** `✗ Failed to send batch after 3 attempts. Dropping X packets.` (Red text).
