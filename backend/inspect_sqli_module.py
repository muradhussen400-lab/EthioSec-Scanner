import sqlite3
import json

con = sqlite3.connect("ethiosec.db")
con.row_factory = sqlite3.Row
cur = con.cursor()

scan = cur.execute("SELECT * FROM scans WHERE id='2fe3b9c6-c08c-4d5d-86b4-63c45ec1d5f6'").fetchone()
if scan:
    chk = json.loads(scan["checks"]) if scan["checks"] else {}
    print("=== CHECKS KEYS ===")
    print(list(chk.keys()))
    print("\n=== MODULE DETAILS ===")
    md = chk.get("module_details", {})
    print(json.dumps(md.get("sqli"), indent=2))
    print("\n=== TIMELINE ===")
    print(json.dumps(chk.get("timeline"), indent=2))
