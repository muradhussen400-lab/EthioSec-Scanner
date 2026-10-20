import pytest
import asyncio
import os
import httpx
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

os.environ["ALLOW_LOCAL_TARGETS"] = "true"

from scanner.engine import SecurityScanner
from scanner.crawler import Crawler
from scanner.http_client import SafeHTTPClient
from scanner.checks.sqli import check_sqli

class MockScanner:
    def __init__(self):
        self.findings = []
    def _add_finding(self, **kwargs):
        self.findings.append(kwargs)

# CSRF storage for rotating tokens
csrf_storage = {"vulnerable": "csrf_vuln_tok_1", "secure": "csrf_sec_tok_1"}

# --- Vulnerable Application (PortSwigger SQLi Login Bypass Model) ---
async def vuln_login_get(request):
    return HTMLResponse(f'''
    <html>
        <body>
            <h1>Account Login</h1>
            <form action="/login" method="POST">
                <input type="hidden" name="csrf" value="{csrf_storage['vulnerable']}" />
                <label>Username</label>
                <input type="text" name="username" />
                <label>Password</label>
                <input type="password" name="password" />
                <button type="submit">Log in</button>
            </form>
        </body>
    </html>
    ''')

async def vuln_login_post(request):
    data = await request.form()
    csrf = data.get("csrf", "")
    username = data.get("username", "")
    password = data.get("password", "")

    expected_csrf = csrf_storage["vulnerable"]
    csrf_storage["vulnerable"] = "csrf_vuln_tok_" + os.urandom(6).hex()

    if csrf != expected_csrf:
        return HTMLResponse("Invalid CSRF token", status_code=400)

    # Vulnerable logic: SQL injection login bypass
    is_bypass = ("' or 1=1--" in username.lower() or 
                 "' or '1'='1" in username.lower() or
                 "administrator'--" in username.lower())

    if is_bypass:
        res = RedirectResponse("/my-account", status_code=302)
        res.set_cookie("session", "user_session_administrator")
        return res
    elif username == "admin" and password == "secret":
        res = RedirectResponse("/my-account", status_code=302)
        res.set_cookie("session", "user_session_admin")
        return res
    else:
        return HTMLResponse(f'''
        <html>
            <body>
                <p class="error">Invalid username or password</p>
                <form action="/login" method="POST">
                    <input type="hidden" name="csrf" value="{csrf_storage['vulnerable']}" />
                    <input type="text" name="username" />
                    <input type="password" name="password" />
                    <button type="submit">Log in</button>
                </form>
            </body>
        </html>
        ''', status_code=200)

async def my_account_get(request):
    if request.method != "GET":
        return HTMLResponse("Method Not Allowed", status_code=405)
    return HTMLResponse("<h1>Your username is: administrator</h1><p>Log out</p>", status_code=200)

vuln_app = Starlette(routes=[
    Route("/login", vuln_login_get, methods=["GET"]),
    Route("/login", vuln_login_post, methods=["POST"]),
    Route("/my-account", my_account_get, methods=["GET"]),
])

# --- Secure Control Application (Parameterized Queries Model) ---
async def sec_login_get(request):
    return HTMLResponse(f'''
    <html>
        <body>
            <h1>Account Login</h1>
            <form action="/login" method="POST">
                <input type="hidden" name="csrf" value="{csrf_storage['secure']}" />
                <label>Username</label>
                <input type="text" name="username" />
                <label>Password</label>
                <input type="password" name="password" />
                <button type="submit">Log in</button>
            </form>
        </body>
    </html>
    ''')

async def sec_login_post(request):
    data = await request.form()
    csrf = data.get("csrf", "")
    username = data.get("username", "")
    password = data.get("password", "")

    expected_csrf = csrf_storage["secure"]
    csrf_storage["secure"] = "csrf_sec_tok_" + os.urandom(6).hex()

    if csrf != expected_csrf:
        return HTMLResponse("Invalid CSRF token", status_code=400)

    # Secure logic: Parameterized query enforces exact string match
    if username == "admin" and password == "secret":
        res = RedirectResponse("/my-account", status_code=302)
        res.set_cookie("session", "user_session_admin")
        return res
    else:
        return HTMLResponse(f'''
        <html>
            <body>
                <p class="error">Invalid username or password</p>
                <form action="/login" method="POST">
                    <input type="hidden" name="csrf" value="{csrf_storage['secure']}" />
                    <input type="text" name="username" />
                    <input type="password" name="password" />
                    <button type="submit">Log in</button>
                </form>
            </body>
        </html>
        ''', status_code=200)

sec_app = Starlette(routes=[
    Route("/login", sec_login_get, methods=["GET"]),
    Route("/login", sec_login_post, methods=["POST"]),
    Route("/my-account", my_account_get, methods=["GET"]),
])

@pytest.mark.asyncio
async def test_sqli_vulnerable_login_bypass_detected():
    """
    Regression Test:
    Ensures EthioSec Scanner detects SQL injection in authentication/login forms
    with CSRF tokens and 302 redirects, validating findings with strong evidence.
    """
    csrf_storage["vulnerable"] = "initial_vuln_token_123"
    transport = httpx.ASGITransport(app=vuln_app)
    
    async with SafeHTTPClient() as client:
        client.client = httpx.AsyncClient(transport=transport, follow_redirects=False)
        
        # 1. Crawler discovers form and fields
        crawler = Crawler("http://127.0.0.1:8000/login", client, max_pages=5, max_depth=2)
        crawl_results = await crawler.run()
        
        forms = crawl_results.get("forms", [])
        endpoints = crawl_results.get("endpoints", [])
        
        assert len(forms) >= 1
        login_form = forms[0]
        assert login_form["action_url"] == "http://127.0.0.1:8000/login"
        assert login_form["method"] == "POST"
        assert "username" in login_form["inputs"]
        assert "csrf" in login_form["inputs"]
        assert "fields" in login_form
        assert login_form["fields"]["csrf"]["value"] == "initial_vuln_token_123"
        
        # 2. Scanner executes check_sqli
        mock_scanner = MockScanner()
        await check_sqli(mock_scanner, endpoints, forms, client)
        
        # 3. Assert finding is generated
        assert len(mock_scanner.findings) == 1
        finding = mock_scanner.findings[0]
        
        assert finding["f_type"] == "sqli"
        assert finding["severity"] == "high"
        assert finding["status"] == "HIGH"
        assert finding["parameter"] == "username"
        assert "SQL Injection via Form Parameter 'username'" in finding["title"]
        assert "boolean diff" in finding["evidence"].lower()
        assert "[!]" in finding["evidence"]

@pytest.mark.asyncio
async def test_sqli_secure_control_no_false_positive():
    """
    Control Test:
    Ensures EthioSec Scanner DOES NOT report SQL injection against a secure,
    parameterized application form under identical test conditions.
    """
    csrf_storage["secure"] = "initial_sec_token_123"
    transport = httpx.ASGITransport(app=sec_app)
    
    async with SafeHTTPClient() as client:
        client.client = httpx.AsyncClient(transport=transport, follow_redirects=False)
        
        crawler = Crawler("http://127.0.0.1:8000/login", client, max_pages=5, max_depth=2)
        crawl_results = await crawler.run()
        
        forms = crawl_results.get("forms", [])
        endpoints = crawl_results.get("endpoints", [])
        
        mock_scanner = MockScanner()
        await check_sqli(mock_scanner, endpoints, forms, client)
        
        # Must produce ZERO findings
        assert len(mock_scanner.findings) == 0

@pytest.mark.asyncio
async def test_safe_http_client_post_redirect_transitions_to_get():
    """
    Verifies that SafeHTTPClient follows RFC 7231 / 9110 rules:
    When a POST receives a 301, 302, or 303 redirect, it transitions to GET
    and drops the request body, avoiding 405 Method Not Allowed errors.
    """
    async def redirecting_post(request):
        return RedirectResponse("/dest", status_code=302)
        
    async def dest_endpoint(request):
        if request.method != "GET":
            return HTMLResponse("Method Not Allowed", status_code=405)
        return HTMLResponse("Destination Reached via GET", status_code=200)

    app = Starlette(routes=[
        Route("/submit", redirecting_post, methods=["POST"]),
        Route("/dest", dest_endpoint, methods=["GET"]),
    ])

    transport = httpx.ASGITransport(app=app)
    async with SafeHTTPClient() as client:
        client.client = httpx.AsyncClient(transport=transport, follow_redirects=False)
        resp = await client.post("http://127.0.0.1:8000/submit", data={"key": "val"})
        assert resp.status_code == 200
        assert resp.text == "Destination Reached via GET"
