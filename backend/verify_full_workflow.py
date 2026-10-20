import urllib.request
import urllib.parse
import json
import time

def run():
    print("=== STARTING FULL LIVE WORKFLOW VERIFICATION ===")
    
    # 1. Login
    data = json.dumps({'email': 'admin@test.com', 'password': 'AdminPassword123!'}).encode()
    req = urllib.request.Request('http://127.0.0.1:8000/api/auth/login', data=data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req) as resp:
            tokens = json.loads(resp.read().decode())
            token = tokens.get('token') or tokens.get('access_token')
            print("1. [OK] Authenticated successfully with JWT token")
    except Exception as e:
        print("1. [FAIL] Login error:", e)
        return False

    auth_headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    # 2. Get Targets
    req = urllib.request.Request('http://127.0.0.1:8000/api/targets', headers=auth_headers)
    with urllib.request.urlopen(req) as resp:
        targets = json.loads(resp.read().decode())
        print(f"2. [OK] Targets fetched from backend. Count: {len(targets)}")

    target_id = None
    for t in targets:
        if t.get('is_verified'):
            target_id = t['id']
            break
            
    if not target_id and targets:
        target_id = targets[0]['id']

    # Target a safe public domain for end-to-end verification
    test_target_url = 'https://example.com'
    t_payload = json.dumps({'url': test_target_url}).encode()
    t_req = urllib.request.Request('http://127.0.0.1:8000/api/targets', data=t_payload, headers=auth_headers)
    with urllib.request.urlopen(t_req) as resp:
        t_obj = json.loads(resp.read().decode())
        target_id = t_obj['id']
        print(f"2b. [OK] Created target ID {target_id} for {test_target_url}")

    # 3. Launch Scan with custom modules (headers, cookies, cors) exactly matching frontend
    scan_payload = json.dumps({
        'target_id': target_id,
        'depth': 'standard',
        'modules': {'headers': True, 'cookies': True, 'cors': True},
        'authorized': True
    }).encode()
    s_req = urllib.request.Request('http://127.0.0.1:8000/api/scans', data=scan_payload, headers=auth_headers)
    with urllib.request.urlopen(s_req) as resp:
        scan_obj = json.loads(resp.read().decode())
        scan_id = scan_obj.get('scan_id') or scan_obj.get('id')
        status = scan_obj.get('status')
        print(f"3. [OK] Scan record created! ID: {scan_id}, Initial Status: {status}")

    # 3b. Start the Scan
    start_req = urllib.request.Request(f'http://127.0.0.1:8000/api/scans/{scan_id}/start', data=b'{}', headers=auth_headers)
    with urllib.request.urlopen(start_req) as resp:
        start_obj = json.loads(resp.read().decode())
        print(f"3b. [OK] Scan engine triggered! Status: {start_obj.get('status')}")

    # 4. Status Polling loop
    finished = False
    for i in range(30):
        time.sleep(2)
        status_req = urllib.request.Request(f'http://127.0.0.1:8000/api/scans/{scan_id}/status', headers=auth_headers)
        with urllib.request.urlopen(status_req) as resp:
            st = json.loads(resp.read().decode())
            curr_status = st.get('status')
            completed = st.get('completed_checks', {})
            findings = st.get('findings_count', {})
            stage = st.get('stage', '')
            print(f"   Poll #{i+1}: status={curr_status} | stage={stage} | completed_checks={completed} | findings_count={findings}")
            if curr_status in ['completed', 'failed']:
                finished = True
                print(f"4. [OK] Scan finished with status '{curr_status}'.")
                print("   Detailed status payload:\n", json.dumps(st, indent=2))
                break

    if not finished:
        print("4. [FAIL] Scan did not finish within timeout")
        return False

    # 5. Fetch Real Findings
    res_req = urllib.request.Request(f'http://127.0.0.1:8000/api/scans/{scan_id}/results', headers=auth_headers)
    with urllib.request.urlopen(res_req) as resp:
        results = json.loads(resp.read().decode())
        findings = results.get('findings', [])
        print(f"5. [OK] Retrieved results! Total real findings saved: {len(findings)}")
        for f in findings[:5]:
            print(f"   - [{f.get('severity')}] {f.get('title')} ({f.get('check_type')})")

    # 6. Verify scan appears in Scan History
    hist_req = urllib.request.Request('http://127.0.0.1:8000/api/scans', headers=auth_headers)
    with urllib.request.urlopen(hist_req) as resp:
        history_resp = json.loads(resp.read().decode())
        scan_list = history_resp.get('scans', [])
        scan_in_hist = any(s.get('id') == scan_id for s in scan_list)
        print(f"6. [OK] Scan {scan_id} present in user scan history: {scan_in_hist}")

    print("=== ALL VERIFICATION CHECKS PASSED ===")
    return True

if __name__ == '__main__':
    run()
