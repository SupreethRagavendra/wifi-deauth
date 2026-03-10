echo "Stopping any existing ML API..."
pkill -f "uvicorn ml_service:app" || true
pkill -f "python app.py" || true
pkill -f "python.app.py" || true
fuser -k 5000/tcp || true
sleep 1

echo "Starting ML API with venv..."
cd /home/supreeth/wif-deauth/ml-api
source venv/bin/activate
python app.py > app.log 2>&1 &
API_PID=$!
sleep 5

echo "════════════════════════════════════════"
echo "LEVEL 4 TEST: ENABLE AGGRESSIVE + HIGH CONFIDENCE"
echo "════════════════════════════════════════"
echo "Enable aggressive mode:"
curl -s -X POST http://localhost:5000/prevention/settings \
  -H "Content-Type: application/json" \
  -d '{"aggressive_mode": true, "intimidation_message": true}' | python -m json.tool

echo "NOTE: Level 4 counter-attack requires monitor mode interface."
echo "If wlan1mon not available, it will log error but not crash."
echo "The prevention_action should show 'counter_attack' in response."

for mac in "Z1:00:00:00:00:01" "Z2:00:00:00:00:02" "Z3:00:00:00:00:03" "Z4:00:00:00:00:04" "Z5:00:00:00:00:05"; do
  curl -s -X POST http://localhost:5000/update-victim \
    -H "Content-Type: application/json" \
    -d "{\"attacker_mac\":\"CO:UN:TE:RA:TT:01\",\"victim_mac\":\"$mac\"}" > /dev/null
done
curl -s -X POST http://localhost:5000/update-session \
  -H "Content-Type: application/json" \
  -d '{"client_mac":"Z1:00:00:00:00:01","bytes_sent":20000}' > /dev/null

for i in $(seq 1 40); do
  curl -s -X POST http://localhost:5000/full-analysis \
    -H "Content-Type: application/json" \
    -d "{\"src_mac\":\"CO:UN:TE:RA:TT:01\",\"dst_mac\":\"Z1:00:00:00:00:01\",\"seq_num\":$((RANDOM)),\"rssi\":-80,\"reason_code\":7,\"channel\":6,\"bssid\":\"AA:BB:CC:DD:EE:FF\"}" > /dev/null
done

curl -s -X POST http://localhost:5000/full-analysis \
  -H "Content-Type: application/json" \
  -d '{"src_mac":"CO:UN:TE:RA:TT:01","dst_mac":"Z1:00:00:00:00:01","seq_num":1111,"rssi":-80,"reason_code":7,"channel":6,"bssid":"AA:BB:CC:DD:EE:FF"}' | python -m json.tool

kill $API_PID
