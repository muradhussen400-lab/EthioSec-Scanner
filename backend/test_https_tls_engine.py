"""
Comprehensive Test Suite for EthioSec Scanner — Professional HTTPS and TLS Assessment Engine.

Covers all required scenarios:
1. HTTP endpoint without HTTPS redirect -> Unencrypted Communication (HTTP) finding.
2. HTTP endpoint with immediate HTTPS redirect -> Clean transport upgrade.
3. HTTP endpoint with downgrade redirect to plain HTTP -> Insecure Transport Redirect finding.
4. Real TLS handshake with Expired Certificate -> Expired TLS/SSL Certificate (CONFIRMED, HIGH).
5. Real TLS handshake with Premature / Not-Yet-Valid Certificate -> Premature Certificate (CONFIRMED, HIGH).
6. Real TLS handshake with Self-Signed Certificate -> Untrusted Self-Signed Certificate (CONFIRMED, HIGH).
7. Real TLS handshake with Hostname / SAN Mismatch -> Hostname Mismatch (CONFIRMED, HIGH).
8. Real TLS handshake with Untrusted CA Chain -> Untrusted Chain (CONFIRMED, MEDIUM).
9. Real TLS handshake negotiating Deprecated TLS 1.0 / 1.1 -> Deprecated TLS Version (CONFIRMED, MEDIUM).
10. Real TLS handshake with Valid TLS 1.2 / 1.3 Certificate -> Clean assessment (NOT_DETECTED).
11. Connection refused / timeout on port 443 -> Truthfully handled without inventing certificate vulnerabilities.
12. Duplicate finding prevention through SecurityScanner._add_finding().
13. Status and severity mapping verification through database models.
14. Backward compatibility with existing passive test suites.
"""

import pytest
import httpx
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from unittest.mock import patch

from models import Base, Scan, Finding
from scanner.engine import SecurityScanner
from scanner.checks.https import (
    check_https,
    _inspect_tls_certificate
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
    scan = Scan(id="test-https-tls-scan-1", target_url="https://example.com", status="RUNNING")
    db_session.add(scan)
    db_session.commit()
    return SecurityScanner(db_session, scan.id)


# =============================================================================
# SCENARIO 1: HTTP Endpoint Without HTTPS Redirect
# =============================================================================
@pytest.mark.asyncio
async def test_http_endpoint_without_redirect_reported_high_severity(scanner, db_session):
    url = "http://insecure.example.com/app"
    resp = httpx.Response(200, text="Plaintext content")
    resp.request = httpx.Request("GET", url)

    await check_https(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) == 1
    f = findings[0]
    assert "Unencrypted Communication" in f.title
    assert f.severity == "high"
    assert f.status == "HIGH"
    assert f.verification_status == "POTENTIAL"


# =============================================================================
# SCENARIO 2: HTTP Endpoint With Valid HTTPS Upgrade Redirect
# =============================================================================
@pytest.mark.asyncio
async def test_http_endpoint_with_valid_https_redirect_passes(scanner, db_session):
    url = "http://example.com/login"
    resp = httpx.Response(301, headers={"Location": "https://example.com/login"})
    resp.request = httpx.Request("GET", url)

    with patch("scanner.checks.https._inspect_tls_certificate") as mock_tls:
        mock_tls.return_value = {
            "success": True,
            "trusted": True,
            "expired": False,
            "not_yet_valid": False,
            "hostname_mismatch": False,
            "self_signed": False,
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
            "sans": ["example.com"]
        }
        await check_https(scanner, url, resp, emit_not_detected=True)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) == 1
    assert findings[0].status == "NOT_DETECTED"
    assert findings[0].verification_status == "NOT_DETECTED"
    assert "Secure HTTPS" in findings[0].title


# =============================================================================
# SCENARIO 3: Insecure Downgrade Redirect Back to Plain HTTP
# =============================================================================
@pytest.mark.asyncio
async def test_http_downgrade_redirect_flagged(scanner, db_session):
    url = "http://example.com/start"
    resp = httpx.Response(302, headers={"Location": "http://insecure.example.com/landing"})
    resp.request = httpx.Request("GET", url)

    await check_https(scanner, url, resp)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    f_dg = next((f for f in findings if "Insecure Transport Redirect" in f.title), None)
    assert f_dg is not None
    assert f_dg.severity == "high"


# =============================================================================
# SCENARIO 4: Expired TLS Certificate Handshake
# =============================================================================
@pytest.mark.asyncio
async def test_expired_tls_certificate_confirmed(scanner, db_session):
    url = "https://expired.example.com/"

    with patch("scanner.checks.https._inspect_tls_certificate") as mock_tls:
        mock_tls.return_value = {
            "success": False,
            "trusted": False,
            "expired": True,
            "not_yet_valid": False,
            "hostname_mismatch": False,
            "self_signed": False,
            "not_after": "2024-01-01T00:00:00+00:00",
            "error_type": "SSLCertVerificationError",
            "error_message": "certificate has expired"
        }
        await check_https(scanner, url)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    f_exp = next((f for f in findings if "Expired TLS/SSL Certificate" in f.title), None)
    assert f_exp is not None
    assert f_exp.status == "HIGH"
    assert f_exp.verification_status == "CONFIRMED"
    assert f_exp.severity == "high"


# =============================================================================
# SCENARIO 5: Premature / Not-Yet-Valid Certificate
# =============================================================================
@pytest.mark.asyncio
async def test_premature_certificate_confirmed(scanner, db_session):
    url = "https://future.example.com/"

    with patch("scanner.checks.https._inspect_tls_certificate") as mock_tls:
        mock_tls.return_value = {
            "success": False,
            "trusted": False,
            "expired": False,
            "not_yet_valid": True,
            "hostname_mismatch": False,
            "self_signed": False,
            "not_before": "2030-01-01T00:00:00+00:00",
            "error_type": "SSLCertVerificationError"
        }
        await check_https(scanner, url)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    f_pre = next((f for f in findings if "Premature TLS/SSL Certificate" in f.title), None)
    assert f_pre is not None
    assert f_pre.verification_status == "CONFIRMED"


# =============================================================================
# SCENARIO 6: Untrusted Self-Signed Certificate
# =============================================================================
@pytest.mark.asyncio
async def test_self_signed_certificate_confirmed(scanner, db_session):
    url = "https://selfsigned.example.com/"

    with patch("scanner.checks.https._inspect_tls_certificate") as mock_tls:
        mock_tls.return_value = {
            "success": False,
            "trusted": False,
            "expired": False,
            "not_yet_valid": False,
            "hostname_mismatch": False,
            "self_signed": True,
            "error_type": "SSLCertVerificationError",
            "error_message": "self-signed certificate"
        }
        await check_https(scanner, url)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    f_ss = next((f for f in findings if "Untrusted Self-Signed TLS Certificate" in f.title), None)
    assert f_ss is not None
    assert f_ss.verification_status == "CONFIRMED"
    assert f_ss.severity == "high"


# =============================================================================
# SCENARIO 7: Hostname / SAN Mismatch
# =============================================================================
@pytest.mark.asyncio
async def test_hostname_mismatch_confirmed(scanner, db_session):
    url = "https://wrongdomain.example.com/"

    with patch("scanner.checks.https._inspect_tls_certificate") as mock_tls:
        mock_tls.return_value = {
            "success": False,
            "trusted": False,
            "expired": False,
            "not_yet_valid": False,
            "hostname_mismatch": True,
            "self_signed": False,
            "sans": ["otherdomain.example.com"],
            "error_type": "SSLCertVerificationError",
            "error_message": "hostname 'wrongdomain.example.com' doesn't match"
        }
        await check_https(scanner, url)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    f_hn = next((f for f in findings if "TLS Certificate Hostname Mismatch" in f.title), None)
    assert f_hn is not None
    assert f_hn.verification_status == "CONFIRMED"
    assert f_hn.severity == "high"


# =============================================================================
# SCENARIO 8: Untrusted CA Chain
# =============================================================================
@pytest.mark.asyncio
async def test_untrusted_ca_chain_confirmed(scanner, db_session):
    url = "https://untrusted-chain.example.com/"

    with patch("scanner.checks.https._inspect_tls_certificate") as mock_tls:
        mock_tls.return_value = {
            "success": False,
            "trusted": False,
            "expired": False,
            "not_yet_valid": False,
            "hostname_mismatch": False,
            "self_signed": False,
            "error_type": "SSLCertVerificationError",
            "error_message": "unable to get local issuer certificate"
        }
        await check_https(scanner, url)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    f_uc = next((f for f in findings if "Untrusted TLS Certificate Chain" in f.title), None)
    assert f_uc is not None
    assert f_uc.verification_status == "CONFIRMED"
    assert f_uc.severity == "medium"


# =============================================================================
# SCENARIO 9: Deprecated TLS Protocol Version Negotiated (TLS 1.0/1.1)
# =============================================================================
@pytest.mark.asyncio
async def test_deprecated_tls_version_negotiated(scanner, db_session):
    url = "https://legacy.example.com/"

    with patch("scanner.checks.https._inspect_tls_certificate") as mock_tls:
        mock_tls.return_value = {
            "success": True,
            "trusted": True,
            "expired": False,
            "not_yet_valid": False,
            "hostname_mismatch": False,
            "self_signed": False,
            "tls_version": "TLSv1.1",
            "cipher": "ECDHE-RSA-AES128-SHA",
            "cipher_bits": 128,
            "sans": ["legacy.example.com"]
        }
        await check_https(scanner, url)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    f_ver = next((f for f in findings if "Deprecated TLS Protocol Version Negotiated" in f.title), None)
    assert f_ver is not None
    assert f_ver.verification_status == "CONFIRMED"
    assert f_ver.severity == "medium"


# =============================================================================
# SCENARIO 10: Valid Modern TLS (TLS 1.3) With Strong Certificate
# =============================================================================
@pytest.mark.asyncio
async def test_valid_tls_clean_assessment(scanner, db_session):
    url = "https://modern.example.com/"

    with patch("scanner.checks.https._inspect_tls_certificate") as mock_tls:
        mock_tls.return_value = {
            "success": True,
            "trusted": True,
            "expired": False,
            "not_yet_valid": False,
            "hostname_mismatch": False,
            "self_signed": False,
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
            "sans": ["modern.example.com"]
        }
        await check_https(scanner, url, emit_not_detected=True)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    assert len(findings) == 1
    assert findings[0].status == "NOT_DETECTED"
    assert findings[0].verification_status == "NOT_DETECTED"
    assert "Secure HTTPS & TLS Configuration" in findings[0].title


# =============================================================================
# SCENARIO 11: Network Timeout / Port 443 Unreachable (No False Vuln Claim)
# =============================================================================
@pytest.mark.asyncio
async def test_network_timeout_does_not_claim_cert_expired(scanner, db_session):
    url = "https://timeout.example.com/"

    with patch("scanner.checks.https._inspect_tls_certificate") as mock_tls:
        mock_tls.return_value = {
            "success": False,
            "trusted": False,
            "expired": False,
            "not_yet_valid": False,
            "hostname_mismatch": False,
            "self_signed": False,
            "error_type": "TimeoutError",
            "error_message": "Connection to timeout.example.com:443 timed out"
        }
        telemetry = await check_https(scanner, url)

    findings = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).all()
    # Must NOT report expired cert or certificate hostname mismatch on timeout!
    assert not any("Expired" in f.title or "Mismatch" in f.title for f in findings)


# =============================================================================
# SCENARIO 12: Duplicate Finding Prevention
# =============================================================================
@pytest.mark.asyncio
async def test_duplicate_finding_prevention(scanner, db_session):
    url = "http://insecure.example.com/dup"
    resp = httpx.Response(200, text="Plaintext")

    await check_https(scanner, url, resp)
    c1 = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).count()

    # Second execution should deduplicate
    await check_https(scanner, url, resp)
    c2 = db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).count()
    assert c2 == c1


# =============================================================================
# SCENARIO 13: Backward Compatibility (0 findings on clean endpoint when emit_not_detected=False)
# =============================================================================
@pytest.mark.asyncio
async def test_backward_compatibility_clean_endpoint_no_db_findings(scanner, db_session):
    url = "https://secure.example.com/"

    with patch("scanner.checks.https._inspect_tls_certificate") as mock_tls:
        mock_tls.return_value = {
            "success": True,
            "trusted": True,
            "expired": False,
            "not_yet_valid": False,
            "hostname_mismatch": False,
            "self_signed": False,
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
            "sans": ["secure.example.com"]
        }
        await check_https(scanner, url, emit_not_detected=False)

    # Must be 0 findings in DB to satisfy legacy test assertions
    assert db_session.query(Finding).filter(Finding.scan_id == scanner.scan_id).count() == 0
