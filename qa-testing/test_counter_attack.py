import sys
import time
sys.path.insert(0, '/home/supreeth/wif-deauth/prevention-engine')
from counter_attack import CounterAttackSystem

# Mock config
config = {
    'level4': {
        'counter_attack_enabled': True,
        'legal_mode': 'conservative'
    }
}

cas = CounterAttackSystem(config)
print("Launching Conservative Counter-Attack against AA:BB:CC:DD:EE:FF...")
cas.launch("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", "conservative")

# Give threads time to run
time.sleep(3)
cas.stop_all()
print("Counter-Attack Test Complete.")
