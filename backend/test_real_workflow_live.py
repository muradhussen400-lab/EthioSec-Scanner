import urllib.request
import urllib.parse
import json
import time
import os
import sys

# Ensure backend imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import SessionLocal
from models import User, ScanTarget, Scan, Finding

def test_live_workflow():
    print("=== STARTING COMPREHENSIVE SCAN EXECUTION VERIFICATION ===")
    
    # 1. Authenticate
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

    # 2. Register / Get Verified Target
    target_url = "https://example.com"
    t_payload = json.dumps({'url': target_url}).encode()
    t_req = urllib.request.Request('http://127.0.0.1:8000/api/targets', data=t_payload, headers=auth_headers)
    with urllib.request.urlopen(t_req) as resp:
        t_obj = json.loads(resp.read().decode())
        target_id = t_obj['id']
        print(f"2. [OK] Target registered: {target_url} (ID: {target_id})")

    # =========================================================================
    # TEST CASE A: Selection Enforcement (SQLi and XSS ONLY)
    # =========================================================================
    print("\n--- Test Case A: SQLi and XSS ONLY selection ---")
    scan_payload_a = json.dumps({
        'target_id': target_id,
        'depth': 'standard',
        'modules': {'sqli': True, 'xss': True},
        'authorized': True
    }).encode()
    
    s_req = urllib.request.Request('http://127.0.0.1:8000/api/scans', data=scan_payload_a, headers=auth_headers)
    with urllib.request.urlopen(s_req) as resp:
        scan_a = json.loads(resp.read().decode())
        scan_id_a = scan_a.get('scan_id') or scan_a.get('id')
        print(f"3a. [OK] Scan record created: {scan_id_a}")

    start_req = urllib.request.Request(f'http://127.0.0.1:8000/api/scans/{scan_id_a}/start', data=b'{}', headers=auth_headers)
    with urllib.request.urlopen(start_req) as resp:
        print(f"3b. [OK] Scan started in background worker.")

    # Poll status until complete
    finished_a = False
    for i in range(30):
        time.sleep(1.5)
        st_req = urllib.request.Request(f'http://127.0.0.1:8000/api/scans/{scan_id_a}/status', headers=auth_headers)
        with urllib.request.urlopen(st_req) as resp:
            st = json.loads(resp.read().decode())
            status = st.get('status')
            prog = st.get('progress')
            stage = st.get('stage')
            mods = st.get('module_details', {})
            timeline = st.get('timeline', [])
            print(f"   Poll #{i+1}: status={status} | progress={prog}% | stage={stage}")
            
            if status in ('completed', 'failed'):
                finished_a = True
                assert status == 'completed', f"Scan A should complete successfully, got {status}"
                assert prog == 100, f"Completed scan progress should be 100%, got {prog}"
                
                # Verify module states
                assert mods['sqli']['selected'] is True
                assert mods['sqli']['status'] == 'completed'
                assert mods['xss']['selected'] is True
                assert mods['xss']['status'] == 'completed'
                
                # Unselected modules must be skipped
                assert mods['headers']['selected'] is False
                assert mods['headers']['status'] == 'skipped'
                assert mods['https']['selected'] is False
                assert mods['https']['status'] == 'skipped'
                assert "not selected" in mods['headers']['message'].lower()
                
                # Verify timeline contains real UTC timestamps
                assert len(timeline) >= 4
                for stage_item in timeline:
                    if stage_item['status'] == 'completed':
                        assert stage_item.get('started_at') is not None
                        assert stage_item.get('finished_at') is not None
                        assert 'T' in stage_item['started_at'], "Timestamp must be ISO-8601 UTC"
                        
                print("   [OK] Selection enforcement verified! SQLi/XSS completed, unselected modules skipped.")
                break

    assert finished_a, "Scan A did not finish within timeout"

    # =========================================================================
    # TEST CASE B: Selection Enforcement (Headers and SSL/TLS ONLY)
    # =========================================================================
    print("\n--- Test Case B: Headers and SSL/TLS ONLY selection ---")
    scan_payload_b = json.dumps({
        'target_id': target_id,
        'depth': 'standard',
        'modules': {'headers': True, 'https': True},
        'authorized': True
    }).encode()
    
    s_req_b = urllib.request.Request('http://127.0.0.1:8000/api/scans', data=scan_payload_b, headers=auth_headers)
    with urllib.request.urlopen(s_req_b) as resp:
        scan_b = json.loads(resp.read().decode())
        scan_id_b = scan_b.get('scan_id') or scan_b.get('id')

    start_req_b = urllib.request.Request(f'http://127.0.0.1:8000/api/scans/{scan_id_b}/start', data=b'{}', headers=auth_headers)
    with urllib.request.urlopen(start_req_b) as resp:
        print(f"4b. [OK] Scan B started in background.")

    finished_b = False
    for i in range(25):
        time.sleep(1.5)
        st_req = urllib.request.Request(f'http://127.0.0.1:8000/api/scans/{scan_id_b}/status', headers=auth_headers)
        with urllib.request.urlopen(st_req) as resp:
            st = json.loads(resp.read().decode())
            status = st.get('status')
            prog = st.get('progress')
            mods = st.get('module_details', {})
            timeline = st.get('timeline', [])
            
            if status in ('completed', 'failed'):
                finished_b = True
                assert status == 'completed'
                assert prog == 100
                assert mods['headers']['selected'] is True
                assert mods['headers']['status'] == 'completed'
                assert mods['https']['selected'] is True
                assert mods['https']['status'] == 'completed'
                assert mods['sqli']['selected'] is False
                assert mods['sqli']['status'] == 'skipped'
                assert mods['xss']['selected'] is False
                assert mods['xss']['status'] == 'skipped'
                
                # Discovery stage should be skipped because only passive checks selected
                disc = next(s for s in timeline if s['id'] == 'discovery')
                assert disc['status'] == 'skipped'
                print("   [OK] Headers & SSL completed, discovery and active checks skipped truthfully.")
                break

    assert finished_b, "Scan B did not finish within timeout"

    # =========================================================================
    # TEST CASE C: Target Blocked / Hostname Resolution Failure
    # =========================================================================
    print("\n--- Test Case C: Target Blocked by SSRF/Resolution ---")
    t_payload_c = json.dumps({'url': 'http://unresolvable-domain-test.local'}).encode()
    t_req_c = urllib.request.Request('http://127.0.0.1:8000/api/targets', data=t_payload_c, headers=auth_headers)
    with urllib.request.urlopen(t_req_c) as resp:
        t_obj_c = json.loads(resp.read().decode())
        target_id_c = t_obj_c['id']

    scan_payload_c = json.dumps({
        'target_id': target_id_c,
        'depth': 'standard',
        'modules': {'headers': True},
        'authorized': True
    }).encode()
    
    s_req_c = urllib.request.Request('http://127.0.0.1:8000/api/scans', data=scan_payload_c, headers=auth_headers)
    with urllib.request.urlopen(s_req_c) as resp:
        scan_c = json.loads(resp.read().decode())
        scan_id_c = scan_c.get('scan_id') or scan_c.get('id')

    start_req_c = urllib.request.Request(f'http://127.0.0.1:8000/api/scans/{scan_id_c}/start', data=b'{}', headers=auth_headers)
    with urllib.request.urlopen(start_req_c) as resp:
        print("5b. [OK] Scan C started.")

    finished_c = False
    for i in range(15):
        time.sleep(1.0)
        st_req = urllib.request.Request(f'http://127.0.0.1:8000/api/scans/{scan_id_c}/status', headers=auth_headers)
        with urllib.request.urlopen(st_req) as resp:
            st = json.loads(resp.read().decode())
            status = st.get('status')
            stage = st.get('stage')
            if status == 'failed':
                finished_c = True
                assert 'Target Validation' in stage or 'Blocked' in stage or 'resolve' in stage.lower()
                print(f"   [OK] Scan C properly marked failed: {stage}")
                break

    assert finished_c, "Scan C did not transition to failed state"

    print("\n=== ALL COMPREHENSIVE WORKFLOW TESTS PASSED CLEANLY ===")
    return True

if __name__ == '__main__':
    test_live_workflow()
