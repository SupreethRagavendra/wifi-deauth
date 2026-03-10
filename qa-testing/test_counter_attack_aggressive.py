import sys
import time
import logging

logging.basicConfig(level=logging.INFO)

sys.path.insert(0, '/home/supreeth/wif-deauth/prevention-engine')
from counter_attack import CounterAttackSystem

config = {
    'level4': {
        'counter_attack_enabled': True,
        'legal_mode': 'aggressive'
    }
}

cas = CounterAttackSystem(config)
print("Launching Aggressive Counter-Attack against AA:BB:CC:DD:EE:FF...")
cas.launch("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", "aggressive")

time.sleep(3)
cas.stop_all()
print("Counter-Attack Test Complete.")
