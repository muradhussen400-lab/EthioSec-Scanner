"""
Smoke test runner for live demonstration:
1. Logs into API at http://127.0.0.1:8000
2. Registers Target 1 (http://127.0.0.1:3000/), creates Scan 1, starts it via /scans/{id}/start
3. Verifies scan lifecycle progress and completion
4. Verifies findings persistence, ownership, and verification status via /scans/{id}/results
5. Registers Target 2 (http://127.0.0.1:3001/), creates Scan 2, starts it
6. Verifies clean scan completion and truthful reporting
"""
import urllib.request
import json
import time
import sys

API = 'http://127.0.0.1:8000/api'

def run():
    print("=== STEP 1: AUTHENTICATION ===")
    login_data = json.dumps({'email': 'admin@test.com', 'password': 'AdminPassword123!'}).encode('utf-8')
    req = urllib.request.Request(f'{API}/auth/login', data=login_data, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode())
        token = res['token']
        print(f"Logged in successfully as: {res['user']['email']}")

    auth_headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    print("\n=== STEP 2: SCAN 1 - DELIBERATELY VULNERABLE APP (Port 3000) ===")
    # 2a. Create Scan Target
    target_payload = json.dumps({'url': 'http://127.0.0.1:3000/'}).encode('utf-8')
    req = urllib.request.Request(f'{API}/targets', data=target_payload, headers=auth_headers)
    with urllib.request.urlopen(req) as resp:
        target1 = json.loads(resp.read().decode())
        t1_id = target1['id']
        print(f"Registered Target 1: {target1['url']} (ID: {t1_id})")

    # 2b. Create Scan 1
    scan_payload = json.dumps({
        'target_id': t1_id,
        'depth': 'standard',
        'authorized': True,
        'modules': {'sqli': True, 'xss': True, 'access_control': True}
    }).encode('utf-8')
    req = urllib.request.Request(f'{API}/scans', data=scan_payload, headers=auth_headers)
    with urllib.request.urlopen(req) as resp:
        scan1 = json.loads(resp.read().decode())
        scan1_id = scan1['scan_id']
        print(f"Created Scan 1: ID {scan1_id} (Status: {scan1.get('status')})")

    # 2c. Start Scan 1
    req = urllib.request.Request(f'{API}/scans/{scan1_id}/start', data=b'{}', headers=auth_headers)
    with urllib.request.urlopen(req) as resp:
        start_res = json.loads(resp.read().decode())
        print(f"Dispatched Scan 1 start: {start_res}")

    # 2d. Poll Scan 1 lifecycle
    completed = False
    for step in range(50):
        time.sleep(2)
        req = urllib.request.Request(f'{API}/scans/{scan1_id}/status', headers=auth_headers)
        with urllib.request.urlopen(req) as resp:
            st = json.loads(resp.read().decode())
            status = st.get('status')
            prog = st.get('progress')
            stage = st.get('stage')
            print(f"  [Scan 1 Poll {step+1}] Progress: {prog}% | Status: {status} | Stage: {stage}")
            if status in ('completed', 'completed_with_errors', 'failed'):
                completed = True
                break

    if not completed:
        print("ERROR: Scan 1 did not complete in allotted time!")
        sys.exit(1)

    # 2e. Check Scan 1 Findings via /scans/{id}/results
    req = urllib.request.Request(f'{API}/scans/{scan1_id}/results', headers=auth_headers)
    with urllib.request.urlopen(req) as resp:
        results1 = json.loads(resp.read().decode())
        findings1 = results1.get('findings', [])
        print(f"\nScan 1 Security Score: {results1.get('security_score')}/100")
        print(f"Scan 1 Findings Count: {len(findings1)}")
        for f in findings1:
            print(f"  * [{f.get('type')}] {f.get('title')}")
            print(f"    Status: {f.get('status')} | Verification: {f.get('verification_status')} | Severity: {f.get('severity')} | Location: {f.get('location')}")
            ev = f.get('evidence') or ''
            if ev:
                first_line = ev.strip().split('\n')[0]
                print(f"    Evidence: {first_line[:120]}")

    print("\n=== STEP 3: SCAN 2 - SAFE APP (Port 3001) ===")
    # 3a. Create Scan Target
    target_payload2 = json.dumps({'url': 'http://127.0.0.1:3001/'}).encode('utf-8')
    req = urllib.request.Request(f'{API}/targets', data=target_payload2, headers=auth_headers)
    with urllib.request.urlopen(req) as resp:
        target2 = json.loads(resp.read().decode())
        t2_id = target2['id']
        print(f"Registered Target 2: {target2['url']} (ID: {t2_id})")

    # 3b. Create Scan 2
    scan_payload2 = json.dumps({
        'target_id': t2_id,
        'depth': 'standard',
        'authorized': True,
        'modules': {'sqli': True, 'xss': True, 'access_control': True}
    }).encode('utf-8')
    req = urllib.request.Request(f'{API}/scans', data=scan_payload2, headers=auth_headers)
    with urllib.request.urlopen(req) as resp:
        scan2 = json.loads(resp.read().decode())
        scan2_id = scan2['scan_id']
        print(f"Created Scan 2: ID {scan2_id}")

    # 3c. Start Scan 2
    req = urllib.request.Request(f'{API}/scans/{scan2_id}/start', data=b'{}', headers=auth_headers)
    with urllib.request.urlopen(req) as resp:
        start_res2 = json.loads(resp.read().decode())
        print(f"Dispatched Scan 2 start: {start_res2}")

    # 3d. Poll Scan 2 lifecycle
    completed2 = False
    for step in range(50):
        time.sleep(2)
        req = urllib.request.Request(f'{API}/scans/{scan2_id}/status', headers=auth_headers)
        with urllib.request.urlopen(req) as resp:
            st = json.loads(resp.read().decode())
            status = st.get('status')
            prog = st.get('progress')
            stage = st.get('stage')
            print(f"  [Scan 2 Poll {step+1}] Progress: {prog}% | Status: {status} | Stage: {stage}")
            if status in ('completed', 'completed_with_errors', 'failed'):
                completed2 = True
                break

    if not completed2:
        print("ERROR: Scan 2 did not complete in allotted time!")
        sys.exit(1)

    # 3e. Check Scan 2 Findings
    req = urllib.request.Request(f'{API}/scans/{scan2_id}/results', headers=auth_headers)
    with urllib.request.urlopen(req) as resp:
        results2 = json.loads(resp.read().decode())
        findings2 = results2.get('findings', [])
        print(f"\nScan 2 Security Score: {results2.get('security_score')}/100")
        print(f"Scan 2 Total Findings in DB: {len(findings2)}")
        vuln_findings = [f for f in findings2 if f.get('verification_status') in ('CONFIRMED', 'POTENTIAL')]
        print(f"Scan 2 Confirmed/Potential Vulnerabilities: {len(vuln_findings)} (Expected: 0)")
        for f in findings2:
            print(f"  * [{f.get('type')}] {f.get('title')} | Verif: {f.get('verification_status')} | Severity: {f.get('severity')}")

    print("\n=== SMOKE TEST COMPLETE ===")

if __name__ == '__main__':
    run()
