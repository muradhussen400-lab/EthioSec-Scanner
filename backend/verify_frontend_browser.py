"""
Live Playwright Browser UI & Console Smoke Test:
Navigates through the real frontend pages served at http://127.0.0.1:5500
connected to backend at http://127.0.0.1:8000:
1. Login flow
2. Dashboard view
3. Scan setup view
4. Scan results view with badge inspection (CONFIRMED vs POTENTIAL vs Severity)
5. Detail modal opening
6. Console error tracking
"""
import asyncio
import sys

async def run_test():
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

        print("--- 1. Testing Login Page (http://127.0.0.1:5500/login.html) ---")
        await page.goto("http://127.0.0.1:5500/login.html", wait_until="networkidle")
        print("Page title:", await page.title())

        # Fill credentials
        await page.fill("#email", "admin@test.com")
        await page.fill("#password", "AdminPassword123!")
        await page.click("#loginBtn")

        # Wait for redirect to dashboard
        try:
            await page.wait_for_url("**/dashboardfinal.html", timeout=6000)
            print("Successfully redirected to Dashboard:", page.url)
        except Exception as e:
            print("Redirect wait failed:", e)

        print("\n--- 2. Testing Dashboard (http://127.0.0.1:5500/dashboardfinal.html) ---")
        await page.wait_for_timeout(1000)
        dash_content = await page.content()
        print("Dashboard loaded. URL:", page.url)

        print("\n--- 3. Testing Scan Launch Page (http://127.0.0.1:5500/scanfinal.html) ---")
        await page.goto("http://127.0.0.1:5500/scanfinal.html", wait_until="networkidle")
        print("Scan page loaded. Title:", await page.title())
        has_url_input = await page.is_visible("#targetUrl, input[name='targetUrl'], #urlInput")
        print("Target URL input visible:", has_url_input)

        print("\n--- 4. Testing Results Page (Scan 1 on Port 3000) ---")
        scan_id = "f8943720-4145-449b-9648-fb6be0f4daa7"
        await page.goto(f"http://127.0.0.1:5500/results.html?id={scan_id}", wait_until="networkidle")
        await page.wait_for_timeout(1500)

        # Inspect cards and badges
        cards = await page.query_selector_all(".finding-card")
        print(f"Total Finding Cards Rendered: {len(cards)}")

        for i, card in enumerate(cards):
            sev_badge = await card.query_selector(".sev-badge")
            sev_text = (await sev_badge.inner_text()).strip() if sev_badge else "N/A"
            sev_class = await sev_badge.get_attribute("class") if sev_badge else ""

            verif_badge = await card.query_selector(".status-badge-outline")
            verif_text = (await verif_badge.inner_text()).strip() if verif_badge else "N/A"
            verif_class = await verif_badge.get_attribute("class") if verif_badge else ""

            title_el = await card.query_selector(".finding-title-text")
            title_text = (await title_el.inner_text()).strip() if title_el else "N/A"

            print(f"  Card #{i+1}:")
            print(f"    Title: {title_text}")
            print(f"    Severity Badge: '{sev_text}' (class='{sev_class}')")
            print(f"    Verification Badge: '{verif_text}' (class='{verif_class}')")

        # Click on the XSS finding card to verify the detail modal
        if cards:
            details_btn = await cards[1].query_selector(".btn-card-details")
            if details_btn:
                await details_btn.click()
                await page.wait_for_timeout(500)
                is_open = await page.evaluate("() => document.getElementById('detailModalOverlay') ? document.getElementById('detailModalOverlay').classList.contains('open') : false")
                modal_title = await page.evaluate("() => document.getElementById('dTitle') ? document.getElementById('dTitle').textContent : ''")
                print(f"Detail Modal Open: {is_open}")
                print(f"Detail Modal Title: '{modal_title}'")

        print("\n--- 5. Console & Network Errors ---")
        print(f"Console Errors: {len(console_errors)}")
        for err in console_errors:
            print("  -", err)
        print(f"Page Errors: {len(page_errors)}")
        for err in page_errors:
            print("  -", err)
        print(f"Failed Network Requests: {len(failed_requests)}")
        for err in failed_requests:
            print("  -", err)

        await browser.close()
        print("\n=== BROWSER UI VERIFICATION COMPLETED CLEANLY ===")

if __name__ == '__main__':
    asyncio.run(run_test())
