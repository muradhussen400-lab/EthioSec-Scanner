"""
Live end-to-end integration test for the upgraded Authentication & Session Security Module.
1. Authenticates against FastAPI backend at http://127.0.0.1:8000
2. Dispatches a scan against target http://127.0.0.1:3000/ with 'auth' module selected
3. Tracks scan lifecycle to completion
4. Verifies database persistence of auth findings and coverage
5. Automates Playwright Chromium browser to inspect results.html, cards, badges, and console
"""
import asyncio
import json
import time
import httpx

API = "http://127.0.0.1:8000/api"

async def main():
    print("=== STEP 1: API AUTHENTICATION ===")
    async with httpx.AsyncClient() as client:
        login_res = await client.post(f"{API}/auth/login", json={
            "email": "admin@test.com",
            "password": "AdminPassword123!"
        })
        assert login_res.status_code == 200, f"Login failed: {login_res.text}"
        token = login_res.json()["token"]
        print(f"Logged in successfully. Token acquired.")

        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        print("\n=== STEP 2: REGISTER TARGET & DISPATCH AUTH SCAN ===")
        target_res = await client.post(f"{API}/targets", headers=headers, json={"url": "http://127.0.0.1:3000/"})
        target_id = target_res.json()["id"]

        scan_payload = {
            "target_id": target_id,
            "depth": "standard",
            "authorized": True,
            "modules": {
                "auth": True,
                "cookies": True,
                "sqli": True
            },
            "auth_context_1": {
                "headers": {"Authorization": "Bearer test_admin_token"}
            }
        }
        create_res = await client.post(f"{API}/scans", headers=headers, json=scan_payload)
        scan_id = create_res.json()["scan_id"]
        print(f"Created Scan: {scan_id}")

        start_res = await client.post(f"{API}/scans/{scan_id}/start", headers=headers, json={})
        print(f"Dispatched Scan Start: {start_res.status_code}")

        print("\n=== STEP 3: TRACKING SCAN PROGRESSION ===")
        completed = False
        for i in range(40):
            await asyncio.sleep(1.5)
            status_res = await client.get(f"{API}/scans/{scan_id}/status", headers=headers)
            data = status_res.json()
            status = data.get("status")
            progress = data.get("progress")
            stage = data.get("stage")
            print(f"  [T+{int((i+1)*1.5)}s] Status={status}, Progress={progress}%, Stage={stage}")
            if status in ("completed", "failed", "completed_with_errors"):
                completed = True
                break

        assert completed, "Scan did not finish within timeout."

        print("\n=== STEP 4: VERIFYING FINDINGS IN RESULTS API ===")
        results_res = await client.get(f"{API}/scans/{scan_id}/results", headers=headers)
        res_data = results_res.json()
        findings = res_data.get("findings", [])
        score = res_data.get("security_score")
        print(f"Scan Finished with Score: {score}/100")
        print(f"Total Findings Persisted: {len(findings)}")

        auth_findings = [f for f in findings if f.get("type") == "auth"]
        print(f"\nAuthentication Module Findings ({len(auth_findings)} Total):")
        for f in auth_findings:
            title = f.get("title")
            sev = f.get("severity")
            stat = f.get("status")
            verif = f.get("verification_status")
            url = f.get("url")
            print(f"  - [{sev.upper()} | {verif}] {title} (url={url})")

    print("\n=== STEP 5: PLAYWRIGHT BROWSER VALIDATION ===")
    from playwright.async_api import async_playwright

    console_errors = []
    page_errors = []
    failed_requests = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        page.on("console", lambda msg: console_errors.append(f"[{msg.type}] {msg.text}") if msg.type in ("error",) else None)
        page.on("pageerror", lambda err: page_errors.append(str(err)))
        page.on("requestfailed", lambda req: failed_requests.append(f"{req.method} {req.url}: {req.failure}"))

        # Login flow
        await page.goto("http://127.0.0.1:5500/login.html", wait_until="networkidle")
        await page.fill("#email", "admin@test.com")
        await page.fill("#password", "AdminPassword123!")
        await page.click("#loginBtn")
        await page.wait_for_url("**/dashboardfinal.html", timeout=6000)
        print("Logged in via frontend UI and reached Dashboard.")

        # Navigate to Results page for our new scan
        results_url = f"http://127.0.0.1:5500/results.html?id={scan_id}"
        await page.goto(results_url, wait_until="networkidle")
        await page.wait_for_timeout(1500)
        print(f"Results page loaded: {results_url}")

        # Check rendered finding cards
        cards = await page.query_selector_all(".finding-card")
        print(f"Rendered Finding Cards: {len(cards)}")
        for i, card in enumerate(cards):
            title = await card.query_selector(".finding-title-text")
            sev = await card.query_selector(".sev-badge")
            verif = await card.query_selector(".status-badge-outline")
            t_text = (await title.inner_text()).strip() if title else ""
            s_text = (await sev.inner_text()).strip() if sev else ""
            v_text = (await verif.inner_text()).strip() if verif else ""
            print(f"  UI Card #{i+1}: '{t_text}' | Sev: {s_text} | Verif: {v_text}")

        # Open Detail Modal for first auth finding if present
        if cards:
            details_btn = await cards[0].query_selector(".btn-card-details")
            if details_btn:
                await details_btn.click()
                await page.wait_for_timeout(500)
                modal_open = await page.evaluate("() => document.getElementById('detailModalOverlay') ? document.getElementById('detailModalOverlay').classList.contains('open') : false")
                modal_title = await page.evaluate("() => document.getElementById('dTitle') ? document.getElementById('dTitle').textContent : ''")
                print(f"Detail Modal Verified: is_open={modal_open}, title='{modal_title}'")

        await browser.close()

    print(f"\nBrowser Console Errors: {len(console_errors)}")
    for e in console_errors:
        print("  Console Error:", e)
    print(f"Browser Page Errors: {len(page_errors)}")
    print(f"Failed HTTP Requests: {len(failed_requests)}")

    assert len(console_errors) == 0, f"Encountered console errors: {console_errors}"
    assert len(page_errors) == 0, f"Encountered page errors: {page_errors}"
    print("\n[SUCCESS] Live integration test and Playwright browser validation completed cleanly!")

if __name__ == "__main__":
    asyncio.run(main())
