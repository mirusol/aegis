"""DEMO utility: simulates an attacker who edits the database directly
(changes a stored hash) to check that `aegis verify` detects the tampering.

Usage:  python tools/tamper_demo.py [cale_db]
"""

import sqlite3
import sys

db = sys.argv[1] if len(sys.argv) > 1 else "data/aegis-sandbox.db"
con = sqlite3.connect(db)
con.execute("UPDATE files SET hash = 'TAMPERED' WHERE rowid = 1")
con.commit()
con.close()
print(f"Database {db} was tampered with (one hash changed). Now run: aegis verify")
