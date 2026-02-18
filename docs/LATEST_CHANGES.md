# Latest Features & Fixes (Feb 9, 2026)

## 1. Clear Recent Packets Feature
- **UI Update:** Added a "Clear History" button next to "Recent Deauth Packets (Last Hour)" on the Admin Dashboard.
- **Backend API:** Implemented `DELETE /api/detection/events` endpoint.
- **Functionality:** Clicking the button clears all in-memory detection events and resets the system status to SAFE immediately.

## 2. Connected Clients Improvement (Mock Data)
- **Problem:** "No clients currently connected" was shown because we are testing without real WiFi clients connected to a monitor interface.
- **Solution:** Modified `WiFiScannerService.java` to return mock client data (iPhone, Samsung, MacBook) when no real clients are found.
- **Benefit:** You can now see how the "Connected Clients" table looks and functions in the UI.

## How to Verify
1. **View Clients:** Go to Admin Dashboard -> Your Networks.
   - Click "Connected Clients". You should see 3 mock devices listed.
2. **Run Attack:** `./keep_attack_active.sh`
   - Dashboard shows UNSAFE and populates detection events.
3. **Clear History:** Click the red "Clear History" button.
   - Events disappear immediately.
   - Status returns to SAFE.

## Verification Script
Run the following script to verify backend API responses:
```bash
./verify_fixes.sh
```
