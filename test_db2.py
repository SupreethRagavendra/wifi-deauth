import sys
import os
sys.path.append(os.path.join(os.getcwd(), 'prevention-engine'))
from db import _conn

def test():
    conn = _conn()
    if conn:
        try:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT institute_code FROM institutes LIMIT 1;")
                code = cursor.fetchone()
                print("Institute Code:", code['institute_code'])
        finally:
            conn.close()

test()
