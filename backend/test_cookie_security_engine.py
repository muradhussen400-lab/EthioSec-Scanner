"""
Comprehensive Test Suite for EthioSec Scanner — Cookie Security Assessment Engine.

Covers all 18 required scenarios:
1. A session cookie with all recommended flags.
2. A session cookie missing 'Secure'.
3. A session cookie missing 'HttpOnly'.
4. Missing SameSite and invalid SameSite values.
5. 'SameSite=None' without 'Secure'.
6. An ordinary preference cookie with limited missing attributes.
7. A cookie whose name is not an obvious session name.
8. Multiple separate Set-Cookie headers.
9. 'Expires' values containing commas.
10. '__Host-' cookies with valid and invalid 'Domain', 'Path', and 'Secure' settings.
11. '__Secure-' and relevant HTTP-related prefixes.
12. Missing response headers.
13. Malformed headers and parser exceptions.
14. Missing 'response.request'.
15. Duplicate observations and repeated scans.
16. Secret redaction in persisted evidence.
17. Correct status and severity mapping through 'SecurityScanner._add_finding()'.
18. No false claim of 'NOT_DETECTED' when no cookies were observed.
"""

import pytest
import httpx
from types import SimpleNamespace
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from models import Base, Scan, Finding
from scanner.engine import SecurityScanner
from scanner.checks.cookies import (
    check_cookies,
    parse_set_cookie,
    sanitize_set_cookie,
    classify_cookie_purpose,
    CookiePurpose
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
    scan = Scan(id="test-cookie-scan-1", target_url="https://example.com", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    return SecurityScanner(db_session, scan.id)


# =============================================================================
# SCENARIO 1: Session cookie with all recommended flags
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_01_session_cookie_all_recommended_flags(scanner, db_session):
    url = "https://example.com/login"
    raw_header = "sessionid=superSecretVal123; Secure; HttpOnly; SameSite=Strict; Path=/"
    resp = httpx.Response(
        200,
        headers=[("set-cookie", raw_header)],
        request=httpx.Request("POST", url)
    )

    await check_cookies(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) == 1
    f = findings[0]
    assert f.status == "NOT_DETECTED"
    assert f.verification_status == "NOT_DETECTED"
    assert f.severity == "info"
    assert "Passed" in f.title
    assert "superSecretVal123" not in (f.evidence or "")
    assert "superSecretVal123" not in f.description


# =============================================================================
# SCENARIO 2: Session cookie missing 'Secure'
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_02_session_cookie_missing_secure(scanner, db_session):
    url = "https://example.com/login"
    raw_header = "sessionid=secret_token_abc; HttpOnly; SameSite=Lax; Path=/"
    resp = httpx.Response(
        200,
        headers=[("set-cookie", raw_header)],
        request=httpx.Request("POST", url)
    )

    await check_cookies(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) == 1
    f = findings[0]
    assert "Missing 'Secure' Attribute" in f.title
    assert f.severity == "medium"
    assert f.status == "MEDIUM"
    assert f.verification_status == "POTENTIAL"
    assert "secret_token_abc" not in f.evidence
    assert "[REDACTED]" in f.evidence


# =============================================================================
# SCENARIO 3: Session cookie missing 'HttpOnly'
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_03_session_cookie_missing_httponly(scanner, db_session):
    url = "https://example.com/login"
    raw_header = "token=auth_secret_xyz; Secure; SameSite=Strict; Path=/"
    resp = httpx.Response(
        200,
        headers=[("set-cookie", raw_header)],
        request=httpx.Request("POST", url)
    )

    await check_cookies(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) == 1
    f = findings[0]
    assert "Missing 'HttpOnly' Attribute" in f.title
    assert f.severity == "medium"
    assert f.status == "MEDIUM"
    assert f.verification_status == "POTENTIAL"
    assert "auth_secret_xyz" not in f.evidence
    assert "[REDACTED]" in f.evidence


# =============================================================================
# SCENARIO 4: Missing SameSite and invalid SameSite values
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_04_missing_and_invalid_samesite(scanner, db_session):
    url = "https://example.com/api"
    # 4A: Missing SameSite
    resp1 = httpx.Response(
        200,
        headers=[("set-cookie", "auth_token=tok123; Secure; HttpOnly; Path=/")],
        request=httpx.Request("GET", url)
    )
    await check_cookies(scanner, url, resp1)

    f1 = db_session.query(Finding).filter(Finding.title.contains("Missing 'SameSite'")).first()
    assert f1 is not None
    assert f1.severity == "low"
    assert f1.verification_status == "POTENTIAL"

    # 4B: Invalid SameSite value
    db_session.query(Finding).delete()
    db_session.commit()

    resp2 = httpx.Response(
        200,
        headers=[("set-cookie", "auth_token=tok123; Secure; HttpOnly; SameSite=InvalidMode; Path=/")],
        request=httpx.Request("GET", url)
    )
    await check_cookies(scanner, url, resp2)

    f2 = db_session.query(Finding).filter(Finding.title.contains("Malformed 'SameSite'")).first()
    assert f2 is not None
    assert f2.severity == "low"
    assert f2.verification_status == "POTENTIAL"


# =============================================================================
# SCENARIO 5: SameSite=None without Secure
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_05_samesite_none_without_secure(scanner, db_session):
    url = "https://example.com/api"
    resp = httpx.Response(
        200,
        headers=[("set-cookie", "sid=token123; HttpOnly; SameSite=None; Path=/")],
        request=httpx.Request("GET", url)
    )

    await check_cookies(scanner, url, resp)

    f = db_session.query(Finding).filter(Finding.title.contains("SameSite=None' Without 'Secure")).first()
    assert f is not None
    assert f.severity == "high"
    assert f.status == "HIGH"
    assert f.verification_status == "CONFIRMED"


# =============================================================================
# SCENARIO 6: Ordinary preference cookie with limited missing attributes
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_06_preference_cookie_limited_missing_attributes(scanner, db_session):
    url = "https://example.com/"
    # Preference cookie with Secure and Path, but missing HttpOnly and SameSite (expected for UI scripts)
    resp = httpx.Response(
        200,
        headers=[("set-cookie", "theme=dark; Secure; Path=/")],
        request=httpx.Request("GET", url)
    )

    await check_cookies(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    # Preference cookies should NOT be flagged with High/Confirmed HttpOnly or CSRF vulnerabilities
    assert not any(f.severity == "high" for f in findings)
    assert not any(f.verification_status == "CONFIRMED" for f in findings)
    assert len(findings) == 1
    assert findings[0].status == "NOT_DETECTED"


# =============================================================================
# SCENARIO 7: Cookie whose name is not an obvious session name
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_07_unfamiliar_cookie_name_classification(scanner, db_session):
    url = "https://example.com/"
    resp = httpx.Response(
        200,
        headers=[("set-cookie", "arbitrary_custom_cookie=val999; Secure; Path=/")],
        request=httpx.Request("GET", url)
    )

    await check_cookies(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    # General cookie should not be treated with high severity confirmation; evaluated as POTENTIAL / low
    assert not any(f.severity == "high" for f in findings)
    assert all(f.verification_status in ("POTENTIAL", "NOT_DETECTED") for f in findings)
    httponly_f = next((f for f in findings if "HttpOnly" in f.title), None)
    if httponly_f:
        assert httponly_f.confidence == "LOW"
        assert "Verify whether this cookie contains sensitive state" in httponly_f.description


# =============================================================================
# SCENARIO 8: Multiple separate Set-Cookie headers
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_08_multiple_separate_headers(scanner, db_session):
    url = "https://example.com/multi"
    resp = httpx.Response(
        200,
        headers=[
            ("set-cookie", "sessionid=sec123; Secure; HttpOnly; SameSite=Strict; Path=/"),
            ("set-cookie", "theme=light; Secure; Path=/"),
            ("set-cookie", "tracking_id=trk456; Secure; HttpOnly; SameSite=Lax; Path=/")
        ],
        request=httpx.Request("GET", url)
    )

    await check_cookies(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) == 1
    assert findings[0].status == "NOT_DETECTED"
    assert "sessionid" in findings[0].description
    assert "theme" in findings[0].description
    assert "tracking_id" in findings[0].description


# =============================================================================
# SCENARIO 9: Expires values containing commas
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_09_expires_values_with_commas(scanner, db_session):
    url = "https://example.com/expires"
    raw = "remember_user=usr1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/; Secure; HttpOnly; SameSite=Lax"
    
    # Test parser directly first
    parsed = parse_set_cookie(raw)
    assert parsed is not None
    assert parsed.name == "remember_user"
    assert parsed.expires == "Wed, 21 Oct 2026 07:28:00 GMT"
    assert parsed.secure is True
    assert parsed.httponly is True
    assert parsed.samesite == "lax"

    resp = httpx.Response(200, headers=[("set-cookie", raw)], request=httpx.Request("GET", url))
    await check_cookies(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) == 1
    assert findings[0].status == "NOT_DETECTED"


# =============================================================================
# SCENARIO 10: __Host- cookies with valid and invalid settings
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_10_host_cookie_prefix_rules(scanner, db_session):
    url = "https://example.com/prefix"

    # 10A: Invalid __Host- cookie (missing Secure, has Domain, path not /)
    resp_invalid = httpx.Response(
        200,
        headers=[("set-cookie", "__Host-sess=abc; Domain=example.com; Path=/api; HttpOnly")],
        request=httpx.Request("GET", url)
    )
    await check_cookies(scanner, url, resp_invalid)

    f_invalid = db_session.query(Finding).filter(Finding.title.contains("Invalid '__Host-' Configuration")).first()
    assert f_invalid is not None
    assert f_invalid.verification_status == "CONFIRMED"
    assert f_invalid.severity == "medium"
    assert "forbidden 'Domain=example.com'" in f_invalid.evidence

    # 10B: Valid __Host- cookie
    db_session.query(Finding).delete()
    db_session.commit()

    resp_valid = httpx.Response(
        200,
        headers=[("set-cookie", "__Host-sess=abc; Secure; Path=/; HttpOnly; SameSite=Strict")],
        request=httpx.Request("GET", url)
    )
    await check_cookies(scanner, url, resp_valid)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) == 1
    assert findings[0].status == "NOT_DETECTED"


# =============================================================================
# SCENARIO 11: __Secure- and relevant HTTP-related prefixes
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_11_secure_and_http_prefixes(scanner, db_session):
    url = "https://example.com/prefix2"

    # 11A: __Secure- without Secure
    resp_sec = httpx.Response(
        200,
        headers=[("set-cookie", "__Secure-token=abc; HttpOnly; Path=/")],
        request=httpx.Request("GET", url)
    )
    await check_cookies(scanner, url, resp_sec)

    f_sec = db_session.query(Finding).filter(Finding.title.contains("__Secure-' Prefix Without 'Secure'")).first()
    assert f_sec is not None
    assert f_sec.verification_status == "CONFIRMED"

    # 11B: __Http- without HttpOnly
    db_session.query(Finding).delete()
    db_session.commit()

    resp_http = httpx.Response(
        200,
        headers=[("set-cookie", "__Http-token=abc; Secure; Path=/")],
        request=httpx.Request("GET", url)
    )
    await check_cookies(scanner, url, resp_http)

    f_http = db_session.query(Finding).filter(Finding.title.contains("Missing 'HttpOnly' Flag")).first()
    assert f_http is not None
    assert f_http.verification_status == "CONFIRMED"


# =============================================================================
# SCENARIO 12: Missing response headers
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_12_missing_response_headers(scanner, db_session):
    url = "https://example.com/empty"
    resp = httpx.Response(200, headers={}, request=httpx.Request("GET", url))

    await check_cookies(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) == 1
    assert findings[0].status == "NOT_TESTED"
    assert findings[0].verification_status == "NOT_TESTED"
    assert "No Set-Cookie Headers" in findings[0].title


# =============================================================================
# SCENARIO 13: Malformed headers and parser exceptions
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_13_malformed_headers(scanner, db_session):
    url = "https://example.com/malformed"
    # Header with malformed Max-Age and invalid date
    raw = "session=tok; Max-Age=not_an_int; Expires=NotADate; Secure; HttpOnly; SameSite=Strict"
    resp = httpx.Response(200, headers=[("set-cookie", raw)], request=httpx.Request("GET", url))

    await check_cookies(scanner, url, resp)

    f = db_session.query(Finding).filter(Finding.title.contains("Malformed Attribute Configuration")).first()
    assert f is not None
    assert f.severity == "low"
    assert f.verification_status == "POTENTIAL"
    assert "Invalid Max-Age" in f.evidence


# =============================================================================
# SCENARIO 14: Missing response.request
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_14_missing_response_request(scanner, db_session):
    url = "https://example.com/no-request"
    # SimpleNamespace mimicking response without request attribute
    fake_resp = SimpleNamespace(
        headers=httpx.Headers([("set-cookie", "session=tok; Secure; HttpOnly; SameSite=Strict; Path=/")])
    )

    await check_cookies(scanner, url, fake_resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) == 1
    assert findings[0].status == "NOT_DETECTED"
    assert findings[0].http_method == "GET"


# =============================================================================
# SCENARIO 15: Duplicate observations and repeated scans
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_15_deduplication(scanner, db_session):
    url = "https://example.com/repeat"
    resp = httpx.Response(
        200,
        headers=[("set-cookie", "session=tok1; Path=/; Secure")],
        request=httpx.Request("GET", url)
    )

    # First check
    await check_cookies(scanner, url, resp)
    initial_count = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).count()

    # Second check on same response
    await check_cookies(scanner, url, resp)
    second_count = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).count()

    # Findings should be deduplicated
    assert initial_count == second_count


# =============================================================================
# SCENARIO 16: Secret redaction in persisted evidence
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_16_secret_redaction(scanner, db_session):
    url = "https://example.com/secret"
    secret_value = "ULTRA_CONFIDENTIAL_AUTH_TOKEN_99999"
    raw = f"sessionid={secret_value}; Path=/"
    resp = httpx.Response(200, headers=[("set-cookie", raw)], request=httpx.Request("GET", url))

    await check_cookies(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) > 0
    for f in findings:
        assert secret_value not in (f.title or "")
        assert secret_value not in (f.description or "")
        assert secret_value not in (f.evidence or "")
        assert secret_value not in (f.request or "")
        assert "[REDACTED]" in (f.evidence or "")


# =============================================================================
# SCENARIO 17: Correct status and severity mapping through _add_finding()
# =============================================================================
# =============================================================================
# SCENARIO 17: Correct status and severity mapping through _add_finding()
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_17_status_severity_mapping(scanner, db_session):
    url = "https://example.com/mapping"
    # Session cookie missing Secure on HTTPS -> POTENTIAL, MEDIUM, medium
    resp = httpx.Response(
        200,
        headers=[("set-cookie", "session=tok; HttpOnly; SameSite=Strict; Path=/")],
        request=httpx.Request("GET", url)
    )

    await check_cookies(scanner, url, resp)

    f = db_session.query(Finding).filter(Finding.title.contains("Missing 'Secure'")).first()
    assert f.status == "MEDIUM"
    assert f.verification_status == "POTENTIAL"
    assert f.severity == "medium"
    assert f.confidence == "MEDIUM"

    # Prefix violation -> CONFIRMED, MEDIUM
    db_session.query(Finding).delete()
    db_session.commit()

    resp_prefix = httpx.Response(
        200,
        headers=[("set-cookie", "__Host-id=xyz; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax")],
        request=httpx.Request("GET", url)
    )
    await check_cookies(scanner, url, resp_prefix)

    f_pfx = db_session.query(Finding).filter(Finding.title.contains("Cookie Prefix Violation")).first()
    assert f_pfx.status == "MEDIUM"
    assert f_pfx.verification_status == "CONFIRMED"
    assert f_pfx.severity == "medium"


# =============================================================================
# SCENARIO 18: No false claim of NOT_DETECTED when no cookies were observed
# =============================================================================
@pytest.mark.asyncio
async def test_scenario_18_no_false_claim_of_not_detected(scanner, db_session):
    url = "https://example.com/nocookies"
    resp = httpx.Response(200, headers={"Content-Type": "text/html"}, request=httpx.Request("GET", url))

    await check_cookies(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) == 1
    # MUST be NOT_TESTED, NEVER NOT_DETECTED
    assert findings[0].status == "NOT_TESTED"
    assert findings[0].verification_status == "NOT_TESTED"
    assert not any(f.status == "NOT_DETECTED" for f in findings)


# =============================================================================
# SCENARIO 19: SecurityScanner._redact_evidence regression testing
# =============================================================================
def test_scenario_19_redact_evidence_regressions(scanner):
    # 1. Cookie headers with colon or equals should be redacted
    t1 = "Observed request header: Cookie: session=super_secret_id_12345; user=alice"
    r1 = scanner._redact_evidence(t1)
    assert "super_secret_id_12345" not in r1
    assert "Cookie=[REDACTED]" in r1

    t2 = "Server response: Set-Cookie: auth_token=secret_jwt_token_999; Path=/"
    r2 = scanner._redact_evidence(t2)
    assert "secret_jwt_token_999" not in r2
    assert "Set-Cookie=[REDACTED]" in r2

    # 2. Authorization header should be redacted
    t3 = "Header: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secretpayload.sig"
    r3 = scanner._redact_evidence(t3)
    assert "secretpayload" not in r3
    assert "Authorization=Bearer [REDACTED]" in r3

    t4 = "Header: Authorization: Basic dXNlcjpwYXNzd29yZA=="
    r4 = scanner._redact_evidence(t4)
    assert "dXNlcjpwYXNzd29yZA==" not in r4
    assert "Authorization=Basic [REDACTED]" in r4

    # 3. Password assignments should be redacted
    t5 = "Body: password = MySuperSecretPassword123"
    r5 = scanner._redact_evidence(t5)
    assert "MySuperSecretPassword123" not in r5
    assert "password=[REDACTED]" in r5

    # 4. Ordinary descriptive English prose must NOT be wiped out
    t6 = "Cookie 'sessionid' was issued without the 'Secure' attribute on an HTTPS endpoint."
    r6 = scanner._redact_evidence(t6)
    assert r6 == t6  # Perfectly preserved!

    t7 = "The session cookie uses the '__Host-' prefix but violates prefix rules: missing 'Secure' attribute."
    r7 = scanner._redact_evidence(t7)
    assert r7 == t7  # Perfectly preserved!
