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
                cursor.execute("SELECT user_id, email, password FROM users LIMIT 1;")
                user = cursor.fetchone()
                print("User:", user)

                # Reset password to a known hash (e.g., "$2a$10$X/7Z8l0j5BXZq4b.nRyhB.qP5aXj.7h9Kj.5mXj5.Zq4b.nRyhB.q" for some password or just use Spring Security bcrypt). Actually easier to register a new admin.
        finally:
            conn.close()

test()
