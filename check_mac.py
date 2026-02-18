import urllib.request
import urllib.error

mac = "10:B1:DF:51:B2:89"
api_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImp0aSI6IjFhYzE2MzQyLWViN2YtNDkzZS05NzM1LWU1YWNjNjYwMWYyZSJ9.eyJpc3MiOiJtYWN2ZW5kb3JzIiwiYXVkIjoibWFjdmVuZG9ycyIsImp0aSI6IjFhYzE2MzQyLWViN2YtNDkzZS05NzM1LWU1YWNjNjYwMWYyZSIsImlhdCI6MTc3MDUzMTQ1NywiZXhwIjoyMDg1MDI3NDU3LCJzdWIiOiIxNzE0MCIsInR5cCI6ImFjY2VzcyJ9.0hggi5DrBzQS88a3WEJ4BdRLC2C0G1AK6slX59DfFih0VXdCVjeljrNm_RKs6pEUzi6B-let0p6cC5eeH-z4iw"

print(f"Checking MAC: {mac}")

# 1. Local Lookup
if mac.upper().startswith("10:B1:DF"):
    print(f"Local DB: Samsung")

# 2. API Lookup
url = f"https://api.macvendors.com/v1/lookup/{mac}"
req = urllib.request.Request(url)
req.add_header("Authorization", f"Bearer {api_token}")
req.add_header("Accept", "text/plain")

try:
    with urllib.request.urlopen(req, timeout=5) as response:
        vendor = response.read().decode('utf-8').strip()
        print(f"API Result: {vendor}")
except Exception as e:
    print(f"API Error: {e}")
