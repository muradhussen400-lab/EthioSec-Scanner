import sqlite3
import json
import os

con = sqlite3.connect("ethiosec.db")
con.row_factory = sqlite3.Row
cur = con.cursor()

scan = cur.execute("SELECT * FROM scans WHERE id='2fe3b9c6-c08c-4d5d-86b4-63c45ec1d5f6'").fetchone()
if scan:
    print("=== SCAN METADATA ===")
    for k in scan.keys():
        val = scan[k]
        if k in ("checks", "modules", "module_details", "pipeline_stages", "timeline", "findings_count") and val:
            try:
                val = json.loads(val)
                print(f"  {k}:\n{json.dumps(val, indent=2)}")
                continue
            except:
                pass
        print(f"  {k}: {val}")

findings = cur.execute("SELECT * FROM findings WHERE scan_id='2fe3b9c6-c08c-4d5d-86b4-63c45ec1d5f6'").fetchall()
print(f"\n=== FINDINGS COUNT: {len(findings)} ===")
for f in findings:
    print("--------------------------------------------------")
    print(f"  ID: {f['id']}")
    print(f"  Type: {f['type']}")
    print(f"  Severity: {f['severity']}")
    print(f"  Confidence: {f['confidence']}")
    print(f"  Status: {f['status']}")
    print(f"  Title: {f['title']}")
    print(f"  URL: {f['url']}")
    print(f"  Parameter: {f['parameter']}")
    print(f"  Evidence:\n{f['evidence']}")

print("\n=== BACKEND LOG (LAST 40 LINES) ===")
if os.path.exists("backend.log"):
    for enc in ["utf-16", "utf-16-le", "utf-8", "latin-1"]:
        try:
            with open("backend.log", "r", encoding=enc) as f:
                lines = f.readlines()
                for line in lines[-40:]:
                    print(line.rstrip())
                break
        except Exception:
            pass
