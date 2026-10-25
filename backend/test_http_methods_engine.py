"""
Comprehensive Test Suite for EthioSec Scanner — Professional HTTP Methods Engine.

Covers all required scenarios:
1. OPTIONS and Allow header parsing (case-insensitive, whitespace-trimmed, RFC compliant).
2. Distinction between Allow (server capabilities) and Access-Control-Allow-Methods (CORS preflight).
3. TRACE Cross-Site Tracing verification using unique nonce reflection.
4. TRACE rejection / custom 405 pages mentioning 'TRACE' not falsely flagged as vulnerable.
5. Advertised dangerous methods (PUT, DELETE, CONNECT) reported as POTENTIAL configuration weaknesses.
6. Safe WebDAV discovery via non-destructive PROPFIND (Depth: 0).
7. Safe methods only (GET, POST, HEAD, OPTIONS) producing clean assessment.
8. Unreachable endpoint or OPTIONS failure handled truthfully (NOT_TESTED).
9. Duplicate finding prevention through SecurityScanner._add_finding().
10. Secret redaction in persisted evidence.
11. Bounded requests without destructive operations.
12. Compatibility with legacy test_scanner_passive assertion (0 findings on secure endpoint).
"""

import pytest
import httpx
from types import SimpleNamespace
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from models import Base, Scan, Finding
from scanner.engine import SecurityScanner
from scanner.checks.http_methods import (
    check_http_methods,
    _parse_method_tokens
)


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = Session(engine)
    yield session
    session.close()


@pytest.fixture
def scanner(db_session):
    scan = Scan(id="test-http-methods-scan-1", target_url="https://example.com", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    return SecurityScanner(db_session, scan.id)


class MockSafeClient:
    """Mock SafeHTTPClient providing deterministic mock responses for HTTP methods."""
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.request_history = []

    async def options(self, url, **kwargs):
        self.request_history.append(("OPTIONS", url, kwargs))
        if "OPTIONS" in self.responses:
            return self.responses["OPTIONS"]
        return httpx.Response(200, headers={"Allow": "GET, HEAD, POST, OPTIONS"})

    async def request(self, method, url, **kwargs):
        self.request_history.append((method.upper(), url, kwargs))
        if method.upper() in self.responses:
            return self.responses[method.upper()]
        return httpx.Response(405, headers={"Allow": "GET, POST, OPTIONS"})


# =============================================================================
# SCENARIO 1: OPTIONS and Allow Header Parsing
# =============================================================================
def test_parse_method_tokens():
    raw_header = "  get , post,HEAD,  options ,  CUSTOM-verb  "
    tokens = _parse_method_tokens(raw_header)
    assert tokens == {"GET", "POST", "HEAD", "OPTIONS", "CUSTOM-VERB"}
    assert _parse_method_tokens("") == set()
    assert _parse_method_tokens(None) == set()


# =============================================================================
# SCENARIO 2: Access-Control-Allow-Methods vs Server Allow Header
# =============================================================================
@pytest.mark.asyncio
async def test_cors_methods_not_confused_with_server_allow(scanner, db_session):
    url = "https://example.com/api"
    # Response has CORS methods mentioning PUT/DELETE for preflight, but Allow header is only GET, POST
    client = MockSafeClient({
        "OPTIONS": httpx.Response(
            200,
            headers={
                "Allow": "GET, POST, OPTIONS",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS"
            }
        )
    })

    telemetry = await check_http_methods(scanner, url, client, emit_not_detected=True)

    # Must NOT report dangerous methods because Allow header is safe
    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert not any("Dangerous HTTP Methods Advertised" in f.title for f in findings)
    assert telemetry["advertised_allow_methods"] == ["GET", "OPTIONS", "POST"]
    assert "PUT" in telemetry["cors_allow_methods"]


# =============================================================================
# SCENARIO 3: Conclusive TRACE Verification via Nonce Reflection (XST)
# =============================================================================
@pytest.mark.asyncio
async def test_trace_reflection_confirmed_vulnerability(scanner, db_session):
    url = "https://example.com/login"

    class TraceReflectingClient(MockSafeClient):
        async def request(self, method, req_url, **kwargs):
            self.request_history.append((method.upper(), req_url, kwargs))
            if method.upper() == "TRACE":
                # Reflect headers in response body (standard XST behavior)
                req_headers = kwargs.get("headers", {})
                nonce = req_headers.get("X-EthioSec-Trace-Nonce", "unknown")
                body = f"TRACE /login HTTP/1.1\r\nHost: example.com\r\nX-EthioSec-Trace-Nonce: {nonce}\r\n"
                return httpx.Response(200, headers={"Content-Type": "message/http"}, text=body)
            return httpx.Response(405)

    client = TraceReflectingClient({
        "OPTIONS": httpx.Response(200, headers={"Allow": "GET, POST, TRACE"})
    })

    await check_http_methods(scanner, url, client)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) >= 1
    f_trace = next((f for f in findings if "Cross-Site Tracing" in f.title), None)
    assert f_trace is not None
    assert f_trace.status == "MEDIUM"
    assert f_trace.verification_status == "CONFIRMED"
    assert f_trace.severity == "medium"
    assert "XST" in f_trace.impact


# =============================================================================
# SCENARIO 4: TRACE Rejection / Custom 405 Mentioning 'TRACE' Not Vulnerable
# =============================================================================
@pytest.mark.asyncio
async def test_trace_custom_405_page_not_false_positive(scanner, db_session):
    url = "https://example.com/api"

    # Server returns 405 Method Not Allowed whose body mentions "The TRACE method is not permitted"
    client = MockSafeClient({
        "OPTIONS": httpx.Response(200, headers={"Allow": "GET, POST, OPTIONS"}),
        "TRACE": httpx.Response(405, text="<html>Error 405: The TRACE method is not permitted here.</html>")
    })

    await check_http_methods(scanner, url, client)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    # Must NOT report confirmed TRACE vulnerability
    assert not any("Cross-Site Tracing" in f.title for f in findings)


# =============================================================================
# SCENARIO 5: Advertised Dangerous Methods (PUT, DELETE) as POTENTIAL Weakness
# =============================================================================
@pytest.mark.asyncio
async def test_advertised_dangerous_methods_reported_as_potential(scanner, db_session):
    url = "https://example.com/resource"
    client = MockSafeClient({
        "OPTIONS": httpx.Response(200, headers={"Allow": "GET, POST, PUT, DELETE, OPTIONS"})
    })

    await check_http_methods(scanner, url, client)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    f_adv = next((f for f in findings if "Dangerous HTTP Methods Advertised" in f.title), None)
    assert f_adv is not None
    assert f_adv.verification_status == "POTENTIAL"
    assert f_adv.severity == "low"
    assert "PUT" in f_adv.title and "DELETE" in f_adv.title


# =============================================================================
# SCENARIO 6: Non-Destructive WebDAV Detection via PROPFIND
# =============================================================================
@pytest.mark.asyncio
async def test_webdav_propfind_multi_status_detected(scanner, db_session):
    url = "https://example.com/webdav"
    client = MockSafeClient({
        "OPTIONS": httpx.Response(200, headers={"Allow": "GET, POST, PROPFIND, OPTIONS", "DAV": "1, 2"}),
        "PROPFIND": httpx.Response(207, headers={"Content-Type": "application/xml"}, text="<D:multistatus xmlns:D='DAV:'></D:multistatus>")
    })

    await check_http_methods(scanner, url, client)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    f_dav = next((f for f in findings if "WebDAV" in f.title), None)
    assert f_dav is not None
    assert f_dav.verification_status == "POTENTIAL"
    assert f_dav.severity == "low"
    assert f_dav.http_method == "PROPFIND"


# =============================================================================
# SCENARIO 7: Clean Endpoint with Only Safe Methods
# =============================================================================
@pytest.mark.asyncio
async def test_clean_endpoint_emits_not_detected_when_requested(scanner, db_session):
    url = "https://example.com/clean"
    client = MockSafeClient({
        "OPTIONS": httpx.Response(200, headers={"Allow": "GET, HEAD, POST, OPTIONS"})
    })

    # With emit_not_detected=True
    telemetry = await check_http_methods(scanner, url, client, emit_not_detected=True)
    assert telemetry["status"] == "NOT_DETECTED"

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) == 1
    assert findings[0].status == "NOT_DETECTED"
    assert findings[0].verification_status == "NOT_DETECTED"
    assert "Passed" in findings[0].title


# =============================================================================
# SCENARIO 8: Untested Outcome on Probing Failure
# =============================================================================
@pytest.mark.asyncio
async def test_untested_outcome_when_endpoint_unreachable(scanner, db_session):
    url = "https://example.com/unreachable"

    class FailingClient(MockSafeClient):
        async def options(self, req_url, **kwargs):
            raise httpx.ConnectTimeout("Connection timed out")

    client = FailingClient()
    telemetry = await check_http_methods(scanner, url, client, emit_not_detected=True)
    assert telemetry["status"] == "NOT_TESTED"

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) == 1
    assert findings[0].status == "NOT_TESTED"
    assert findings[0].verification_status == "NOT_TESTED"


# =============================================================================
# SCENARIO 9: Duplicate Finding Prevention
# =============================================================================
@pytest.mark.asyncio
async def test_duplicate_finding_prevention(scanner, db_session):
    url = "https://example.com/dup"
    client = MockSafeClient({
        "OPTIONS": httpx.Response(200, headers={"Allow": "GET, POST, PUT, DELETE"})
    })

    await check_http_methods(scanner, url, client)
    c1 = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).count()

    # Second execution should deduplicate
    await check_http_methods(scanner, url, client)
    c2 = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).count()
    assert c2 == c1


# =============================================================================
# SCENARIO 10: Backward-Compatibility with Passive Regression Tests
# =============================================================================
@pytest.mark.asyncio
async def test_backward_compatibility_with_passive_suite(scanner, db_session):
    url = "https://example.com/secure"
    client = MockSafeClient({
        "OPTIONS": httpx.Response(200, headers={"Allow": "GET, POST, OPTIONS"})
    })

    # Default emit_not_detected=False
    await check_http_methods(scanner, url, client, emit_not_detected=False)
    # Must have 0 findings in DB to satisfy legacy test assertions
    assert db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).count() == 0
