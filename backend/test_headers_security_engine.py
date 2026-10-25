"""
Comprehensive Test Suite for EthioSec Scanner — Professional HTTP Security Headers Engine.

Covers all 15 required scenarios:
1. All relevant headers present with sensible values.
2. Individual missing headers.
3. Invalid or malformed header values.
4. CSP enforcing versus report-only.
5. CSP frame-ancestors and X-Frame-Options interaction.
6. CSP weak directives and contextual classification.
7. HSTS on HTTPS versus HTTP responses.
8. HSTS max-age parsing, including malformed values.
9. Case-insensitive header names.
10. Multiple or repeated header values where HTTP library permits them.
11. Empty response headers and response-inspection failures.
12. Duplicate finding prevention.
13. Status/severity mapping through the real scanner integration.
14. Evidence sanitization and compatibility with _redact_evidence().
15. No false claim of a clean assessment when checks were not performed.
"""

import pytest
import httpx
from types import SimpleNamespace
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from models import Base, Scan, Finding
from scanner.engine import SecurityScanner
from scanner.checks.headers import (
    check_security_headers,
    _parse_csp_directives,
    VALID_REFERRER_POLICIES
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
    scan = Scan(id="test-headers-scan-1", target_url="https://example.com", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    return SecurityScanner(db_session, scan.id)


# =============================================================================
# SCENARIO 1: All relevant headers present with sensible values
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_01_all_headers_present_sensible_values(scanner, db_session):
    url = "https://example.com/app"
    resp = httpx.Response(
        200,
        headers={
            "content-type": "text/html; charset=utf-8",
            "content-security-policy": (
                "default-src 'self'; script-src 'self'; object-src 'none'; "
                "base-uri 'self'; frame-ancestors 'self'"
            ),
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=(), camera=(), microphone=()"
        },
        request=httpx.Request("GET", url)
    )

    await check_security_headers(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) == 1
    f = findings[0]
    assert f.status == "NOT_DETECTED"
    assert f.verification_status == "NOT_DETECTED"
    assert f.severity == "info"
    assert "Passed" in f.title


# =============================================================================
# SCENARIO 2: Individual missing headers
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_02_individual_missing_headers(scanner, db_session):
    url = "https://example.com/page"

    # Base secure headers
    secure_set = {
        "content-type": "text/html; charset=utf-8",
        "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-content-type-options": "nosniff",
        "x-frame-options": "SAMEORIGIN",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=()"
    }

    # 2a. Missing CSP
    h = dict(secure_set)
    del h["content-security-policy"]
    resp = httpx.Response(200, headers=h, request=httpx.Request("GET", url))
    await check_security_headers(scanner, url, resp)
    f = db_session.query(Finding).filter(Finding.title == "Content-Security-Policy Not Set").first()
    assert f is not None
    assert f.severity == "medium"
    assert f.verification_status == "POTENTIAL"

    # 2b. Missing HSTS
    db_session.query(Finding).delete()
    h = dict(secure_set)
    del h["strict-transport-security"]
    resp = httpx.Response(200, headers=h, request=httpx.Request("GET", url))
    await check_security_headers(scanner, url, resp)
    f = db_session.query(Finding).filter(Finding.title == "HSTS Not Set").first()
    assert f is not None
    assert f.severity == "medium"
    assert f.verification_status == "POTENTIAL"

    # 2c. Missing X-Content-Type-Options
    db_session.query(Finding).delete()
    h = dict(secure_set)
    del h["x-content-type-options"]
    resp = httpx.Response(200, headers=h, request=httpx.Request("GET", url))
    await check_security_headers(scanner, url, resp)
    f = db_session.query(Finding).filter(Finding.title == "Missing X-Content-Type-Options").first()
    assert f is not None
    assert f.severity == "low"
    assert f.verification_status == "POTENTIAL"

    # 2d. Missing framing protection (both frame-ancestors and X-Frame-Options omitted)
    db_session.query(Finding).delete()
    h = dict(secure_set)
    h["content-security-policy"] = "default-src 'self'; object-src 'none'; base-uri 'self'"
    del h["x-frame-options"]
    resp = httpx.Response(200, headers=h, request=httpx.Request("GET", url))
    await check_security_headers(scanner, url, resp)
    f = db_session.query(Finding).filter(
        Finding.title == "Missing Framing Protection (X-Frame-Options / CSP frame-ancestors Absent)"
    ).first()
    assert f is not None
    assert f.severity == "medium"
    assert f.verification_status == "POTENTIAL"

    # 2e. Missing Referrer-Policy
    db_session.query(Finding).delete()
    h = dict(secure_set)
    del h["referrer-policy"]
    resp = httpx.Response(200, headers=h, request=httpx.Request("GET", url))
    await check_security_headers(scanner, url, resp)
    f = db_session.query(Finding).filter(Finding.title == "Referrer-Policy Not Set").first()
    assert f is not None
    assert f.severity == "low"
    assert f.verification_status == "POTENTIAL"

    # 2f. Missing Permissions-Policy
    db_session.query(Finding).delete()
    h = dict(secure_set)
    del h["permissions-policy"]
    resp = httpx.Response(200, headers=h, request=httpx.Request("GET", url))
    await check_security_headers(scanner, url, resp)
    f = db_session.query(Finding).filter(Finding.title == "Permissions-Policy Not Set").first()
    assert f is not None
    assert f.severity == "low"
    assert f.verification_status == "POTENTIAL"


# =============================================================================
# SCENARIO 3: Invalid or malformed header values
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_03_invalid_or_malformed_header_values(scanner, db_session):
    url = "https://example.com/api"

    # 3a. Invalid X-Content-Type-Options
    resp = httpx.Response(
        200,
        headers={"x-content-type-options": "invalid-sniff"},
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_cto = db_session.query(Finding).filter(
        Finding.title.contains("Invalid X-Content-Type-Options")
    ).first()
    assert f_cto is not None
    assert "invalid-sniff" in f_cto.title

    # 3b. Obsolete X-Frame-Options ALLOW-FROM
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={"x-frame-options": "ALLOW-FROM https://partner.example.com"},
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_xfo = db_session.query(Finding).filter(
        Finding.title == "Obsolete X-Frame-Options Value ('ALLOW-FROM')"
    ).first()
    assert f_xfo is not None

    # 3c. Invalid X-Frame-Options unrecognized directive
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={"x-frame-options": "ALLOWALL"},
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_xfo_inv = db_session.query(Finding).filter(
        Finding.title.contains("Invalid X-Frame-Options Header Value")
    ).first()
    assert f_xfo_inv is not None
    assert "ALLOWALL" in f_xfo_inv.title

    # 3d. Invalid Referrer-Policy
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={"referrer-policy": "bogus-policy"},
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_rp = db_session.query(Finding).filter(
        Finding.title.contains("Invalid Referrer-Policy Directive")
    ).first()
    assert f_rp is not None
    assert "bogus-policy" in f_rp.title

    # 3e. Empty Permissions-Policy
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={"permissions-policy": "    "},
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_pp = db_session.query(Finding).filter(
        Finding.title == "Malformed Permissions-Policy Header (Empty Directive String)"
    ).first()
    assert f_pp is not None


# =============================================================================
# SCENARIO 4: CSP enforcing versus report-only
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_04_csp_enforcing_vs_report_only(scanner, db_session):
    url = "https://example.com/csp-test"

    # Only Report-Only header present (no enforcing CSP)
    resp = httpx.Response(
        200,
        headers={
            "content-security-policy-report-only": "default-src 'self'; report-uri /csp-report"
        },
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)

    f = db_session.query(Finding).filter(
        Finding.title == "Content-Security-Policy Not Set (Report-Only Mode Active)"
    ).first()
    assert f is not None
    assert f.severity == "low"
    assert f.verification_status == "POTENTIAL"
    assert "report-only" in f.description.lower()
    assert "not block" in f.description.lower()

    # Enforcing CSP present alongside Report-Only
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={
            "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
            "content-security-policy-report-only": "default-src 'self'; report-uri /csp-report"
        },
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)

    # Should NOT have missing CSP or report-only finding
    f_missing = db_session.query(Finding).filter(
        Finding.title.contains("Content-Security-Policy Not Set")
    ).first()
    assert f_missing is None


# =============================================================================
# SCENARIO 5: CSP frame-ancestors and X-Frame-Options interaction
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_05_frame_ancestors_and_xfo_interaction(scanner, db_session):
    url = "https://example.com/framing"

    # Case A: CSP includes frame-ancestors, X-Frame-Options is ABSENT
    # Under W3C CSP Level 2/3, frame-ancestors supersedes XFO. No framing finding should be reported.
    resp = httpx.Response(
        200,
        headers={
            "content-security-policy": "default-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'"
        },
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)

    f_frame = db_session.query(Finding).filter(
        Finding.title.contains("Framing")
    ).first()
    assert f_frame is None

    # Case B: CSP lacks frame-ancestors, but X-Frame-Options is SAMEORIGIN
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={
            "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'",
            "x-frame-options": "SAMEORIGIN"
        },
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)

    f_frame = db_session.query(Finding).filter(
        Finding.title.contains("Framing")
    ).first()
    assert f_frame is None

    # Case C: Neither frame-ancestors nor X-Frame-Options is provided
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'"
        },
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)

    f_frame = db_session.query(Finding).filter(
        Finding.title == "Missing Framing Protection (X-Frame-Options / CSP frame-ancestors Absent)"
    ).first()
    assert f_frame is not None
    assert f_frame.severity == "medium"

    # Case D: Multiple CSP headers (httpx headers list) where one has frame-ancestors
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers=[
            ("content-security-policy", "default-src 'self'"),
            ("content-security-policy", "frame-ancestors 'self'; object-src 'none'; base-uri 'self'")
        ],
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_frame_multi = db_session.query(Finding).filter(
        Finding.title.contains("Framing")
    ).first()
    assert f_frame_multi is None

    # Case E: Report-Only CSP has frame-ancestors, but Enforced CSP does not and XFO is absent
    # MUST still report missing framing defense because report-only does not protect framing!
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'",
            "content-security-policy-report-only": "frame-ancestors 'self'"
        },
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_frame_ro = db_session.query(Finding).filter(
        Finding.title == "Missing Framing Protection (X-Frame-Options / CSP frame-ancestors Absent)"
    ).first()
    assert f_frame_ro is not None
    assert f_frame_ro.severity == "medium"


# =============================================================================
# SCENARIO 6: CSP weak directives and contextual classification
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_06_csp_weak_directives(scanner, db_session):
    url = "https://example.com/csp-weak"

    # 6a. unsafe-inline without nonce or hash
    resp = httpx.Response(
        200,
        headers={
            "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'"
        },
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_ui = db_session.query(Finding).filter(
        Finding.title == "Weak Content-Security-Policy: 'unsafe-inline' Allowed"
    ).first()
    assert f_ui is not None
    assert f_ui.severity == "medium"
    assert f_ui.verification_status == "POTENTIAL"

    # 6b. unsafe-inline WITH a cryptographic nonce (modern standard backward compat)
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={
            "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-rAnd0m123'; object-src 'none'; base-uri 'self'"
        },
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_ui_nonce = db_session.query(Finding).filter(
        Finding.title == "Weak Content-Security-Policy: 'unsafe-inline' Allowed"
    ).first()
    assert f_ui_nonce is None

    # 6c. unsafe-eval
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={
            "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'self'"
        },
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_ue = db_session.query(Finding).filter(
        Finding.title == "Weak Content-Security-Policy: 'unsafe-eval' Allowed"
    ).first()
    assert f_ue is not None
    assert f_ue.severity == "low"

    # 6d. Wildcard script source
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={
            "content-security-policy": "default-src 'self'; script-src 'self' *; object-src 'none'; base-uri 'self'"
        },
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_wc = db_session.query(Finding).filter(
        Finding.title == "Weak Content-Security-Policy: Wildcard Script Source"
    ).first()
    assert f_wc is not None

    # 6e. Missing object-src
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={
            "content-security-policy": "default-src 'self'; script-src 'self'; base-uri 'self'"
        },
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_obj = db_session.query(Finding).filter(
        Finding.title == "Weak Content-Security-Policy: Missing 'object-src' Restriction"
    ).first()
    assert f_obj is not None

    # 6f. Missing base-uri
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={
            "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'"
        },
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_base = db_session.query(Finding).filter(
        Finding.title == "Weak Content-Security-Policy: Missing 'base-uri' Directive"
    ).first()
    assert f_base is not None


# =============================================================================
# SCENARIO 7: HSTS on HTTPS versus HTTP responses
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_07_hsts_https_vs_http_responses(scanner, db_session):
    # 7a. Plain HTTP origin with HSTS returned -> RFC 6797 non-conformance observation
    http_url = "http://insecure.example.com/index"
    resp = httpx.Response(
        200,
        headers={"strict-transport-security": "max-age=31536000; includeSubDomains"},
        request=httpx.Request("GET", http_url)
    )
    await check_security_headers(scanner, http_url, resp)
    f_http_hsts = db_session.query(Finding).filter(
        Finding.title == "HSTS Header Sent Over Insecure HTTP Origin"
    ).first()
    assert f_http_hsts is not None
    assert f_http_hsts.severity == "low"
    assert "rfc 6797" in f_http_hsts.description.lower()

    # 7b. Plain HTTP origin without HSTS -> should NOT claim HSTS is missing on HTTP
    db_session.query(Finding).delete()
    resp = httpx.Response(200, headers={"content-type": "text/html"}, request=httpx.Request("GET", http_url))
    await check_security_headers(scanner, http_url, resp)
    f_missing_http = db_session.query(Finding).filter(
        Finding.title == "HSTS Not Set"
    ).first()
    assert f_missing_http is None

    # 7c. HTTPS origin without HSTS -> Missing HSTS finding
    db_session.query(Finding).delete()
    https_url = "https://secure.example.com/index"
    resp = httpx.Response(200, headers={"content-type": "text/html"}, request=httpx.Request("GET", https_url))
    await check_security_headers(scanner, https_url, resp)
    f_missing_https = db_session.query(Finding).filter(
        Finding.title == "HSTS Not Set"
    ).first()
    assert f_missing_https is not None
    assert f_missing_https.severity == "medium"


# =============================================================================
# SCENARIO 8: HSTS max-age parsing, including malformed values
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_08_hsts_max_age_parsing(scanner, db_session):
    url = "https://example.com/hsts"

    # 8a. Missing max-age directive
    resp = httpx.Response(
        200,
        headers={"strict-transport-security": "includeSubDomains; preload"},
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_no_age = db_session.query(Finding).filter(
        Finding.title == "Malformed HSTS Header: Missing 'max-age' Directive"
    ).first()
    assert f_no_age is not None

    # 8b. Invalid non-integer max-age
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={"strict-transport-security": "max-age=one_year; includeSubDomains"},
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_inv_age = db_session.query(Finding).filter(
        Finding.title.contains("Invalid 'max-age' Value ('one_year')")
    ).first()
    assert f_inv_age is not None

    # 8c. max-age=0 (disabling HSTS pin)
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={"strict-transport-security": "max-age=0"},
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_zero = db_session.query(Finding).filter(
        Finding.title == "HSTS Policy Disabled ('max-age=0')"
    ).first()
    assert f_zero is not None
    assert f_zero.severity == "medium"

    # 8d. Short max-age duration (< 120 days)
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={"strict-transport-security": "max-age=3600; includeSubDomains"},
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_short = db_session.query(Finding).filter(
        Finding.title == "HSTS Header With Short 'max-age' Duration"
    ).first()
    assert f_short is not None
    assert f_short.severity == "low"

    # 8e. Valid long max-age (1 year)
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={"strict-transport-security": "max-age=31536000; includeSubDomains; preload"},
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_hsts_err = db_session.query(Finding).filter(
        Finding.title.contains("HSTS")
    ).first()
    assert f_hsts_err is None

    # 8f. Negative max-age value (RFC 6797 syntax error)
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={"strict-transport-security": "max-age=-10"},
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_neg = db_session.query(Finding).filter(
        Finding.title.contains("Negative 'max-age' Value ('-10')")
    ).first()
    assert f_neg is not None
    assert f_neg.severity == "low"

    # 8g. Duplicate max-age directives (RFC 6797 §6.1 syntax error)
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={"strict-transport-security": "max-age=31536000; max-age=0"},
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_dup = db_session.query(Finding).filter(
        Finding.title == "Malformed HSTS Header: Duplicate 'max-age' Directives"
    ).first()
    assert f_dup is not None
    assert f_dup.severity == "low"


# =============================================================================
# SCENARIO 9: Case-insensitive header names
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_09_case_insensitive_headers(scanner, db_session):
    url = "https://example.com/casing"
    resp = httpx.Response(
        200,
        headers={
            "cOnTeNt-TyPe": "text/html; charset=utf-8",
            "CoNtEnT-sEcUrItY-pOlIcY": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
            "sTrIcT-tRaNsPoRt-SeCuRiTy": "max-age=31536000; includeSubDomains",
            "X-cOnTeNt-TyPe-OpTiOnS": "nosniff",
            "X-fRaMe-OpTiOnS": "SAMEORIGIN",
            "rEfErReR-pOlIcY": "strict-origin-when-cross-origin",
            "pErMiSsIoNs-PoLiCy": "camera=(), microphone=()"
        },
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) == 1
    assert findings[0].status == "NOT_DETECTED"
    assert "Passed" in findings[0].title


# =============================================================================
# SCENARIO 10: Multiple or repeated header values
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_10_multiple_header_values(scanner, db_session):
    url = "https://example.com/multi-tokens"

    # Multiple Referrer-Policy tokens (browser uses the last recognized value)
    resp = httpx.Response(
        200,
        headers={
            "referrer-policy": "no-referrer, strict-origin-when-cross-origin"
        },
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_rp_inv = db_session.query(Finding).filter(
        Finding.title.contains("Referrer-Policy")
    ).all()
    # Both are valid; neither is unsafe-url
    assert not any("Insecure" in f.title or "Invalid" in f.title for f in f_rp_inv)

    # Final token is unsafe-url
    db_session.query(Finding).delete()
    resp = httpx.Response(
        200,
        headers={
            "referrer-policy": "strict-origin, unsafe-url"
        },
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)
    f_unsafe = db_session.query(Finding).filter(
        Finding.title == "Insecure Referrer-Policy ('unsafe-url')"
    ).first()
    assert f_unsafe is not None
    assert f_unsafe.severity == "low"


# =============================================================================
# SCENARIO 11: Empty response headers and response-inspection failures
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_11_empty_headers_and_exceptions(scanner, db_session):
    url = "https://example.com/empty"

    # 11a. Empty response headers -> NOT_TESTED finding
    resp = httpx.Response(200, headers={}, request=httpx.Request("GET", url))
    await check_security_headers(scanner, url, resp)
    f_empty = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(f_empty) == 1
    assert f_empty[0].status == "NOT_TESTED"
    assert f_empty[0].verification_status == "NOT_TESTED"
    assert "Not Tested" in f_empty[0].title

    # 11b. Response object whose headers extraction raises Exception
    db_session.query(Finding).delete()
    broken_resp = SimpleNamespace(request=SimpleNamespace(method="GET"))
    # accessing broken_resp.headers will raise AttributeError
    await check_security_headers(scanner, url, broken_resp)
    f_err = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(f_err) == 1
    assert f_err[0].status == "NOT_TESTED"  # Empty headers fallback or error handling


# =============================================================================
# SCENARIO 12: Duplicate finding prevention
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_12_duplicate_finding_prevention(scanner, db_session):
    url = "https://example.com/duplicate-test"
    resp = httpx.Response(
        200,
        headers={"content-type": "text/html"},
        request=httpx.Request("GET", url)
    )

    # First execution emits missing header findings
    await check_security_headers(scanner, url, resp)
    count_1 = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).count()
    assert count_1 > 0

    # Second execution on identical response should deduplicate
    await check_security_headers(scanner, url, resp)
    count_2 = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).count()
    assert count_2 == count_1


# =============================================================================
# SCENARIO 13: Status / severity mapping through the real scanner integration
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_13_status_and_severity_mapping(scanner, db_session):
    url = "https://example.com/status-check"
    resp = httpx.Response(
        200,
        headers={"content-type": "text/html"},
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    for f in findings:
        # Crucial architectural requirement: Missing headers are configuration observations,
        # NOT confirmed exploitable vulnerabilities!
        assert f.verification_status == "POTENTIAL"
        assert f.verification_status != "CONFIRMED"
        assert f.severity in ("medium", "low")


# =============================================================================
# SCENARIO 14: Evidence sanitization and compatibility with _redact_evidence()
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_14_evidence_sanitization(scanner, db_session):
    url = "https://example.com/sensitive"
    # Even if an Authorization token was reflected in a header
    resp = httpx.Response(
        200,
        headers={
            "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-eval'",
            "authorization": "Bearer superSecretToken12345"
        },
        request=httpx.Request("GET", url)
    )
    await check_security_headers(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    for f in findings:
        assert "superSecretToken12345" not in (f.evidence or "")
        assert "superSecretToken12345" not in f.description


# =============================================================================
# SCENARIO 15: No false claim of a clean assessment when checks were not performed
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_15_no_false_claim_of_clean_assessment(scanner, db_session):
    url = "https://example.com/untested"

    # Completely empty headers
    resp = httpx.Response(200, headers={}, request=httpx.Request("GET", url))
    await check_security_headers(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    # Must NOT claim NOT_DETECTED (clean pass)
    assert not any(f.status == "NOT_DETECTED" for f in findings)
    assert any(f.status == "NOT_TESTED" for f in findings)


# =============================================================================
# HELPER TEST: CSP directive parsing nuances (W3C §4.2.1 duplicate precedence)
# =============================================================================
def test_csp_directive_parsing_w3c_compliance():
    # Duplicate directive: first occurrence MUST be preserved, duplicate ignored
    raw_csp = "default-src 'self'; ScRiPt-SrC 'self' https://trusted.com; script-src *; object-src 'none'"
    parsed = _parse_csp_directives(raw_csp)
    assert "script-src" in parsed
    # Must preserve the first instance ('self', 'https://trusted.com'), NOT the duplicate '*'
    assert parsed["script-src"] == ["'self'", "https://trusted.com"]
    assert parsed["object-src"] == ["'none'"]
    assert parsed["default-src"] == ["'self'"]
