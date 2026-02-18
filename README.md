# Wi-Fi Security Platform

A real-time Wi-Fi Deauthentication Attack Detection System.

## Quick Start (3 Terminals)

Open 3 separate terminals and run the following commands in order:

### Terminal 1: Backend (API)
```bash
make run-backend
```
*Wait until you see "Started WifiSecurityApplication..."*

### Terminal 2: Frontend (Dashboard)
```bash
make run-frontend
```
*Wait until the browser opens automatically at http://localhost:3000*

### Terminal 3: Packet Sniffer (Detection Engine)
```bash
make run-sniffer
```
*Enter your sudo password when prompted. This starts the real-time packet capture on `wlan1`.*

## First Time Setup
If this is your first time running the project, install dependencies first:
```bash
make setup
```

## Troubleshooting
- **Permission Denied:** Ensure you have sudo access for `run-sniffer`.
- **Interface Not Found:** Ensure `wlan1` is plugged in and recognized by `iwconfig`.
- **Port In Use:** Run `lsof -ti:8080 | xargs kill -9` to free up the backend port.
