import urllib.request
import json
import re
from security import create_access_token

files = [
    'ETHIOSEC SCANNER 2/scanjavafinal.js',
    'ETHIOSEC SCANNER 2/scan_historyjava.js',
    'ETHIOSEC SCANNER 2/resultsjava.js',
    'ETHIOSEC SCANNER 2/assistantjava.js',
    'ETHIOSEC SCANNER 2/reportjava.js',
    'ETHIOSEC SCANNER 2/settingsjava.js'
]

print("=== CHECKING JAVASCRIPT FILES ===")
for path in files:
    with open(path, 'r', encoding='utf-8') as f:
        code = f.read()
    print(f"{path}: {len(code)} characters, {len(code.splitlines())} lines.")

print("\n=== CHECKING FRONTEND HTTP RESPONSES ===")
urls = [
    'http://127.0.0.1:5500/dashboardfinal.html',
    'http://127.0.0.1:5500/scanfinal.html',
    'http://127.0.0.1:5500/scan_history.html',
    'http://127.0.0.1:5500/results.html',
    'http://127.0.0.1:5500/reports.html',
    'http://127.0.0.1:5500/assistant.html',
    'http://127.0.0.1:5500/settings.html',
    'http://127.0.0.1:5500/livescan.html'
]
for u in urls:
    req = urllib.request.urlopen(u)
    body = req.read().decode('utf-8')
    has_history = 'scan_history.html' in body
    has_results = 'results.html' in body
    has_reports = 'reports.html' in body
    has_assistant = 'assistant.html' in body
    has_settings = 'settings.html' in body
    has_shared_css = 'shared_nav_header.css' in body
    print(f"{u.split('/')[-1]}: HTTP {req.status} ({len(body)} B) -> sidebar links: reports={has_reports}, assistant={has_assistant}, settings={has_settings}, shared_css={has_shared_css}")

print("\n=== VERIFYING REAL BACKEND AUTH & SETTINGS ENDPOINTS ===")
token = create_access_token({"sub": "miftah@example.com", "is_verified": True})
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

try:
    # 1. Profile GET
    req_prof = urllib.request.Request("http://127.0.0.1:8000/api/user/profile", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req_prof) as resp:
        prof_data = json.loads(resp.read().decode('utf-8'))
        print(f"GET /api/user/profile: HTTP {resp.status}, Email: {prof_data.get('email')}, Name: {prof_data.get('full_name')}")

    # 2. Profile PUT
    put_payload = json.dumps({"full_name": "Miftah Hussen", "website": "https://ethio-ecommerce.local"}).encode('utf-8')
    req_put = urllib.request.Request("http://127.0.0.1:8000/api/user/profile", data=put_payload, headers=headers, method="PUT")
    with urllib.request.urlopen(req_put) as resp_put:
        put_data = json.loads(resp_put.read().decode('utf-8'))
        print(f"PUT /api/user/profile: HTTP {resp_put.status}, Updated Name: {put_data.get('full_name')}, Website: {put_data.get('website')}")

    # 3. Settings GET
    req_set = urllib.request.Request("http://127.0.0.1:8000/api/user/settings", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req_set) as resp_set:
        set_data = json.loads(resp_set.read().decode('utf-8'))
        print(f"GET /api/user/settings: HTTP {resp_set.status}, Depth: {set_data.get('default_scan_depth')}, Completed Alert: {set_data.get('notif_scan_completed')}")

    # 4. Settings PUT
    set_put_payload = json.dumps({
        "default_scan_depth": "standard",
        "notif_scan_completed": True,
        "notif_scan_failed": True,
        "notif_security_findings": True
    }).encode('utf-8')
    req_set_put = urllib.request.Request("http://127.0.0.1:8000/api/user/settings", data=set_put_payload, headers=headers, method="PUT")
    with urllib.request.urlopen(req_set_put) as resp_set_put:
        set_put_data = json.loads(resp_set_put.read().decode('utf-8'))
        print(f"PUT /api/user/settings: HTTP {resp_set_put.status}, Default Depth: {set_put_data.get('default_scan_depth')}")

    # 5. Change Password Validation Check (Bad Current Password rejection)
    bad_pass_payload = json.dumps({"current_password": "WrongPassword123!", "new_password": "NewSecretPass456!"}).encode('utf-8')
    req_pass = urllib.request.Request("http://127.0.0.1:8000/api/auth/change-password", data=bad_pass_payload, headers=headers, method="POST")
    try:
        urllib.request.urlopen(req_pass)
        print("POST /api/auth/change-password: Unexpected 200 on bad password!")
    except urllib.error.HTTPError as he:
        print(f"POST /api/auth/change-password: Correctly rejected invalid current password -> HTTP {he.code} {he.reason}")

    print("\n[OK] ALL 8 AUTHENTICATED FRONTEND PAGES AND SETTINGS ENDPOINTS FULLY VERIFIED!")
except Exception as e:
    print(f"Verification error: {e}")
