import sys
import os
import json
sys.path.append(os.path.join(os.getcwd(), 'prevention-engine'))
from db import _conn

def test():
    conn = _conn()
    if conn:
        try:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT email, role, mac_address FROM users LIMIT 10;")
                users = cursor.fetchall()
                print("Users:", json.dumps(users, indent=2))
        finally:
            conn.close()

test()
