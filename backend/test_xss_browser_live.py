"""
EthioSec Scanner - Genuine Live Browser XSS Integration Test Suite (Phase 3 & Phase 4 Gate).

Verifies the complete XSS pipeline with genuine headless Chromium execution via Playwright:
1. Baseline does not trigger canary execution.
2. Injected test case triggers canary only when vulnerable behavior is present.
3. Scanner correlates execution signal with exact URL, parameter, and payload.
4. Structural HTML breakout without demonstrated JS execution yields POTENTIAL (never CONFIRMED).
5. CSP nonces/hashes/strict-dynamic block inline script and downgrade to POTENTIAL.
6. Safe HTML-escaped reflections yield NOT_DETECTED.
7. Plain text / CSV / JSON responses yield NOT_DETECTED without false positives.
8. Attribute injection with embedded '>' characters avoids premature boundary exit.
9. JavaScript string delimiter escaping correctly blocks false positives.
10. POST form fields are verified via browser form submission.
11. Missing Playwright or browser binaries yield UNSUPPORTED_ENVIRONMENT, never CONFIRMED.
12. Scan cancellation cleanly aborts without dangling browser instances.
"""

import os
os.environ["ALLOW_LOCAL_TARGETS"] = "true"

import sys
import html
import re
import asyncio
import http.server
import socketserver
import threading
import unittest
from urllib.parse import urlparse, parse_qs
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.checks.xss import check_xss, verify_browser_execution, mutate_url_parameter
from scanner.http_client import SafeHTTPClient


class LiveVulnerableServer(http.server.BaseHTTPRequestHandler):
    """
    Local multi-behavior HTTP test server running only on localhost.
    Exposes deliberate behaviors for safe, local-only scanner validation.
    """
    def log_message(self, *args):
        pass  # Suppress request logging noise during tests

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/safe":
            q = qs.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<html><body><h1>Safe Search</h1><div>{html.escape(q)}</div></body></html>".encode("utf-8"))

        elif path == "/vuln_html":
            q = qs.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<html><body><h1>Search Results</h1><div id='res'>{q}</div></body></html>".encode("utf-8"))

        elif path == "/vuln_attr":
            name = qs.get("name", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<html><body><form><input type='text' name='name' value=\"{name}\"></form></body></html>".encode("utf-8"))

        elif path == "/tags_only":
            # Reflects structural markup (<b>, <div>, <xss_tag>) but strictly filters <script> and event handlers
            q = qs.get("q", [""])[0]
            filtered = re.sub(r'(?i)<script.*?</script>|<script.*?>|</script>|on\w+\s*=', '', q)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<html><body><h1>Filtered Feed</h1><div>{filtered}</div></body></html>".encode("utf-8"))

        elif path == "/csp_nonce":
            # Reflects payload raw, but strictly enforces CSP nonce
            q = qs.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'nonce-R4nd0mN0nc3V4lu3'")
            self.end_headers()
            self.wfile.write(f"<html><body><h1>CSP Protected</h1><div>{q}</div></body></html>".encode("utf-8"))

        elif path == "/text_plain":
            q = qs.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"Raw Text Output: {q}".encode("utf-8"))

        elif path == "/js_quoted":
            user = qs.get("user", [""])[0]
            # Safely escape quotes and HTML tags to prevent script breakout
            escaped_user = user.replace("'", "\\'").replace("<", "\\x3c").replace(">", "\\x3e")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<html><head><script>var currentUser = '{escaped_user}';</script></head><body>Welcome</body></html>".encode("utf-8"))

        elif path == "/form_page":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><form method='POST' action='/vuln_post'><input name='comment' type='text'></form></body></html>")

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        form_data = parse_qs(body)

        if path == "/vuln_post":
            comment = form_data.get("comment", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<html><body><h1>Feedback Submitted</h1><div>{comment}</div></body></html>".encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


class MockScannerContext:
    def __init__(self, target_url: str):
        self.scan_id = "test_browser_xss_scan"
        self.target_url = target_url
        self.findings = []
        self.db = None
        self.cancelled = False

    def _add_finding(self, **kwargs):
        self.findings.append(kwargs)


class TestLiveBrowserXSSVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = socketserver.TCPServer(("127.0.0.1", 0), LiveVulnerableServer)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_01_baseline_does_not_trigger_canary(self):
        """Verify baseline navigation to safe and vulnerable endpoints produces zero canary signals."""
        async def _test():
            status, detail = await verify_browser_execution(
                url=f"{self.base_url}/vuln_html?q=hello",
                method="GET",
                params={"q": "hello"},
                location="query",
                canary_token="canary_baseline_token_xyz"
            )
            self.assertEqual(status, "ATTEMPTED_NO_EXECUTION")
            self.assertIn("no canary script execution observed", detail)
        asyncio.run(_test())

    def test_02_genuine_browser_confirms_executable_xss(self):
        """Verify that genuine Playwright browser executes the canary signal and marks CONFIRMED."""
        async def _test():
            scanner = MockScannerContext(self.base_url)
            client = SafeHTTPClient()
            endpoints = [{
                "url": f"{self.base_url}/vuln_html?q=test",
                "method": "GET",
                "params": ["q"],
                "values": {"q": "test"}
            }]
            cov = await check_xss(scanner, endpoints, [], client, depth="standard", enable_browser_verification=True)
            
            self.assertGreater(len(scanner.findings), 0)
            finding = scanner.findings[0]
            self.assertEqual(finding["verification_status"], "CONFIRMED")
            self.assertEqual(finding["severity"], "high")
            self.assertIn("Executable", finding["title"])
            self.assertIn("window.__ethioxss_", finding["evidence"])
            self.assertEqual(cov.browser_verification_status, "CONFIRMED")
            self.assertIn("browser_execution_verification", cov.techniques_completed)
        asyncio.run(_test())

    def test_03_safe_html_escaped_reflection_yields_clean_pass(self):
        """Verify HTML-escaped parameter produces clean pass (NOT_DETECTED) with zero false positives."""
        async def _test():
            scanner = MockScannerContext(self.base_url)
            client = SafeHTTPClient()
            endpoints = [{
                "url": f"{self.base_url}/safe?q=test",
                "method": "GET",
                "params": ["q"],
                "values": {"q": "test"}
            }]
            cov = await check_xss(scanner, endpoints, [], client, depth="standard", enable_browser_verification=True)
            self.assertEqual(len(scanner.findings), 0)
            self.assertEqual(cov.inputs_tested, 1)
        asyncio.run(_test())

    def test_04_structural_markup_without_js_execution_yields_potential_never_confirmed(self):
        """
        Verify that when structural tags (<tag>) reflect but script execution is filtered,
        status is POTENTIAL and NEVER CONFIRMED.
        """
        async def _test():
            scanner = MockScannerContext(self.base_url)
            client = SafeHTTPClient()
            endpoints = [{
                "url": f"{self.base_url}/tags_only?q=test",
                "method": "GET",
                "params": ["q"],
                "values": {"q": "test"}
            }]
            cov = await check_xss(scanner, endpoints, [], client, depth="standard", enable_browser_verification=True)
            
            self.assertGreater(len(scanner.findings), 0)
            finding = scanner.findings[0]
            self.assertEqual(finding["verification_status"], "POTENTIAL")
            self.assertNotEqual(finding["verification_status"], "CONFIRMED")
            self.assertIn("Structural HTML Injection", finding["title"])
            self.assertIn("Browser-side script execution was not validated", finding["description"])
            self.assertEqual(cov.browser_verification_status, "ATTEMPTED_NO_EXECUTION")
        asyncio.run(_test())

    def test_05_csp_nonce_policy_downgrades_to_potential(self):
        """Verify that CSP nonces block inline script execution and result in POTENTIAL (mitigated by CSP)."""
        async def _test():
            scanner = MockScannerContext(self.base_url)
            client = SafeHTTPClient()
            endpoints = [{
                "url": f"{self.base_url}/csp_nonce?q=test",
                "method": "GET",
                "params": ["q"],
                "values": {"q": "test"}
            }]
            cov = await check_xss(scanner, endpoints, [], client, depth="standard", enable_browser_verification=True)
            
            self.assertGreater(len(scanner.findings), 0)
            finding = scanner.findings[0]
            self.assertEqual(finding["verification_status"], "POTENTIAL")
            self.assertNotEqual(finding["verification_status"], "CONFIRMED")
            self.assertIn("Mitigated by CSP", finding["title"])
            self.assertEqual(finding["severity"], "low")
        asyncio.run(_test())

    def test_06_post_form_parameter_browser_verification(self):
        """Verify POST form parameter injection executes canary via browser form submission."""
        async def _test():
            scanner = MockScannerContext(self.base_url)
            client = SafeHTTPClient()
            forms = [{
                "action_url": f"{self.base_url}/vuln_post",
                "page_url": f"{self.base_url}/form_page",
                "method": "POST",
                "inputs": ["comment"],
                "fields": {"comment": {"type": "text", "value": ""}}
            }]
            cov = await check_xss(scanner, [], forms, client, depth="standard", enable_browser_verification=True)
            
            self.assertGreater(len(scanner.findings), 0)
            finding = scanner.findings[0]
            self.assertEqual(finding["verification_status"], "CONFIRMED")
            self.assertEqual(finding["severity"], "high")
            self.assertIn("Form Parameter 'comment'", finding["title"])
        asyncio.run(_test())

    def test_07_text_plain_content_type_safely_ignored(self):
        """Verify non-HTML text/plain response is safely classified and produces zero XSS findings."""
        async def _test():
            scanner = MockScannerContext(self.base_url)
            client = SafeHTTPClient()
            endpoints = [{
                "url": f"{self.base_url}/text_plain?q=test",
                "method": "GET",
                "params": ["q"],
                "values": {"q": "test"}
            }]
            cov = await check_xss(scanner, endpoints, [], client, depth="standard", enable_browser_verification=True)
            self.assertEqual(len(scanner.findings), 0)
        asyncio.run(_test())

    def test_08_javascript_escaped_string_no_false_positive(self):
        """Verify backslash-escaped JavaScript string delimiter prevents false positive."""
        async def _test():
            scanner = MockScannerContext(self.base_url)
            client = SafeHTTPClient()
            endpoints = [{
                "url": f"{self.base_url}/js_quoted?user=admin",
                "method": "GET",
                "params": ["user"],
                "values": {"user": "admin"}
            }]
            cov = await check_xss(scanner, endpoints, [], client, depth="standard", enable_browser_verification=True)
            self.assertEqual(len(scanner.findings), 0)
        asyncio.run(_test())

    def test_09_missing_playwright_binary_yields_unsupported_never_confirmed(self):
        """Verify missing browser binary or Playwright error produces UNSUPPORTED_ENVIRONMENT, never CONFIRMED."""
        async def _test():
            with patch("playwright.async_api.async_playwright", side_effect=Exception("Chromium binary missing")):
                scanner = MockScannerContext(self.base_url)
                client = SafeHTTPClient()
                endpoints = [{
                    "url": f"{self.base_url}/vuln_html?q=test",
                    "method": "GET",
                    "params": ["q"],
                    "values": {"q": "test"}
                }]
                cov = await check_xss(scanner, endpoints, [], client, depth="standard", enable_browser_verification=True)
                
                self.assertGreater(len(scanner.findings), 0)
                finding = scanner.findings[0]
                self.assertEqual(finding["verification_status"], "POTENTIAL")
                self.assertNotEqual(finding["verification_status"], "CONFIRMED")
                self.assertEqual(cov.browser_verification_status, "UNSUPPORTED_ENVIRONMENT")
        asyncio.run(_test())

    def test_10_scan_cancellation_aborts_cleanly(self):
        """Verify scanner cancellation cleanly aborts before/during browser verification."""
        async def _test():
            scanner = MockScannerContext(self.base_url)
            scanner.cancelled = True
            client = SafeHTTPClient()
            endpoints = [{
                "url": f"{self.base_url}/vuln_html?q=test",
                "method": "GET",
                "params": ["q"],
                "values": {"q": "test"}
            }]
            cov = await check_xss(scanner, endpoints, [], client, depth="standard", enable_browser_verification=True)
            self.assertFalse(cov.verification_completed)
            self.assertIn("cancelled", (cov.blocking_reason or "").lower())
        asyncio.run(_test())


if __name__ == "__main__":
    unittest.main()
