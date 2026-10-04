import requests
import json
import time

def run_e2e():
    BASE_URL = 'http://127.0.0.1:8000/api'
    print('Starting E2E API Test...')

    # 1. Register/Login
    print('1. Registering user test2@example.com...')
    res = requests.post(f'{BASE_URL}/auth/register', json={
        'email': 'test2@example.com',
        'password': 'password123!',
        'full_name': 'Test User'
    })
    if res.status_code == 409:
        print('User already exists, logging in...')
        res = requests.post(f'{BASE_URL}/auth/login', json={
            'email': 'test2@example.com',
            'password': 'password123!'
        })
        
    if res.status_code != 200:
        print(f'Auth Failed: {res.text}')
        return

    token = res.json().get('token')
    headers = {'Authorization': f'Bearer {token}'}
    print(f'Auth Success! Token: {token[:10]}...')

    # 2. Create Target
    print('2. Creating target http://example.com...')
    res = requests.post(f'{BASE_URL}/targets', json={'url': 'http://example.com'}, headers=headers)
    if res.status_code != 200:
        print(f'Target Create Failed: {res.text}')
        return
    target_id = res.json().get('scan_id') or res.json().get('id')
    print(f'Target Created! ID: {target_id}')

    # 3. Create Scan (SQLi only)
    print('3. Creating scan for SQLi only...')
    res = requests.post(f'{BASE_URL}/scans', json={
        'target_id': target_id,
        'depth': 'standard',
        'modules': {'sqli': True, 'xss': False, 'headers': False},
        'authorized': True
    }, headers=headers)
    if res.status_code != 200:
        print(f'Scan Create Failed: {res.text}')
        return
    scan_id = res.json().get('scan_id') or res.json().get('id')
    print(f'Scan Created! ID: {scan_id}')

    # 4. Start Scan
    print('4. Starting scan...')
    res = requests.post(f'{BASE_URL}/scans/{scan_id}/start', headers=headers)
    if res.status_code != 200:
        print(f'Scan Start Failed: {res.text}')
        return
    print('Scan Started successfully.')

    # 5. Poll Status
    print('5. Polling status...')
    while True:
        res = requests.get(f'{BASE_URL}/scans/{scan_id}/status', headers=headers)
        if res.status_code != 200:
            print(f'Status Poll Failed: {res.text}')
            break
        data = res.json()
        status = data.get('status')
        progress = data.get('progress')
        print(f'   Status: {status} | Progress: {progress}%')
        if status in ['completed', 'failed', 'error']:
            break
        time.sleep(2)

    # 6. Get Results
    print('6. Fetching results...')
    res = requests.get(f'{BASE_URL}/scans/{scan_id}/results', headers=headers)
    if res.status_code != 200:
        print(f'Results Fetch Failed: {res.text}')
        return

    results = res.json()
    print('--- FINAL RESULTS ---')
    print(json.dumps(results, indent=2))

if __name__ == '__main__':
    run_e2e()
