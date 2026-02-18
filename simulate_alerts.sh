#!/bin/bash
# simulate_alerts.sh
# Sends random detection alerts to the backend to populate the dashboard

echo "==================================================="
echo "   🛡️  Wi-Fi Security - Alert Simulation Tool   🛡️"
echo "==================================================="
echo "Target: http://localhost:8080/api/detection/alert"
echo "Press [CTRL+C] to stop."
echo ""

while true; do
  # generate random values
  RAND=$((RANDOM % 3))
  PACKETS=$((RANDOM % 150 + 20))
  CHANNEL=$((RANDOM % 11 + 1))
  SIGNAL=$((RANDOM % 50 + 30)) # 30 to 80
  SIGNAL="-$SIGNAL"
  
  if [ $RAND -eq 0 ]; then
    TYPE="DEAUTH_FLOOD"
    SEVERITY="CRITICAL"
    MSG="High volume deauth flood detected affecting multiple clients"
    ATTACKER="AA:BB:CC:DD:EE:FF"
    TARGET="FF:EE:DD:CC:BB:AA"
  elif [ $RAND -eq 1 ]; then
    TYPE="TARGETED_DEAUTH"
    SEVERITY="HIGH"
    MSG="Persistent targeted deauth attack on specific client"
    ATTACKER="11:22:33:44:55:66"
    TARGET="66:55:44:33:22:11"
  else
    TYPE="ROGUE_AP_DEAUTH"
    SEVERITY="MEDIUM"
    MSG="Suspicious deauthentication frames from unknown AP"
    ATTACKER="00:11:22:33:44:55"
    TARGET="BROADCAST"
  fi

  TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  # Send request
  RESPONSE=$(curl -s -X POST http://localhost:8080/api/detection/alert \
    -H "Content-Type: application/json" \
    -d "{
      \"type\": \"$TYPE\",
      \"severity\": \"$SEVERITY\",
      \"message\": \"$MSG\",
      \"attackerMac\": \"$ATTACKER\",
      \"targetBssid\": \"$TARGET\",
      \"packetCount\": $PACKETS,
      \"channel\": $CHANNEL,
      \"signal\": $SIGNAL,
      \"timestamp\": \"$TIMESTAMP\"
    }")

  echo "[$(date +%T)] Sent $TYPE ($SEVERITY) - Signal: ${SIGNAL}dBm"
  
  # Random sleep between 2 and 6 seconds
  sleep $((RANDOM % 5 + 2))
done
