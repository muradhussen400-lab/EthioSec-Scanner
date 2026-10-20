import pytest
import datetime
import os
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse

os.environ["ALLOW_LOCAL_TARGETS"] = "true"

from database import SessionLocal, engine, Base
from models import User, Scan, Finding, ScanTarget, UserSettings
from scanner.engine import SecurityScanner
from scanner.crawler import Crawler
from scanner.checks.sqli import check_sqli, SQLiCoverageRecord
from scanner.checks.xss import check_xss, XSSCoverageRecord
from schemas import ScanCreate, ScanResultOut
from ai.executive_summary import generate_executive_summary, map_finding_to_category, aggregate_finding_counts

class MockResponse:
    def __init__(self, status_code=200, text="<html><body>OK</body></html>", headers=None, duration=0.05):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8")
        self.headers = headers or {"Content-Type": "text/html; charset=utf-8"}
        self.duration = duration
        self.elapsed = datetime.timedelta(seconds=duration)
        self._elapsed = datetime.timedelta(seconds=duration)
        self.request = MagicMock()
        self.extensions = {}

class MockHTTPClient:
    def __init__(self, default_response=None, response_factory=None):
        self.default_response = default_response or MockResponse()
        self.response_factory = response_factory
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        if self.response_factory:
            return self.response_factory("GET", url, kwargs)
        return self.default_response

    async def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        if self.response_factory:
            return self.response_factory("POST", url, kwargs)
        return self.default_response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.fixture(autouse=True)
def mock_is_safe():
    with patch("scanner.engine.is_safe_url", return_value=True), \
         patch("scanner.safety.is_safe_url", return_value=True), \
         patch("scanner.http_client.is_safe_url", return_value=True):
        yield


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


# ==============================================================================
# CASE 1: Zero discovered parameters and zero forms must NOT produce Not Detected
# ==============================================================================
@pytest.mark.asyncio
async def test_case_1_zero_discovered_parameters_produces_inconclusive_not_clean(db_session):
    user = User(email=f"sqli_c1_{os.urandom(4).hex()}@test.com", password_hash="hash")
    db_session.add(user)
    db_session.commit()

    scan = Scan(
        user_id=user.id,
        target_url="https://empty-surface.test/",
        depth="standard",
        status="running",
        modules={"sqli": True}
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)
    endpoints = [{"url": "https://empty-surface.test/", "method": "GET", "params": [], "param_values": {}}]
    forms = []
    client = MockHTTPClient()

    # Direct check_sqli execution
    coverage = await check_sqli(scanner, endpoints, forms, client, depth="standard")
    assert isinstance(coverage, SQLiCoverageRecord)
    assert coverage.candidate_inputs_discovered == 0
    assert coverage.inputs_tested == 0
    assert coverage.requests_completed == 0
    assert coverage.blocking_reason is not None

    # Full engine execution block test
    with patch("scanner.checks.sqli.check_sqli", AsyncMock(return_value=coverage)):
        with patch("scanner.engine.SafeHTTPClient", return_value=client):
            with patch("scanner.engine.Crawler.run", AsyncMock(return_value={"urls": [scan.target_url], "endpoints": endpoints, "forms": forms})):
                await scanner.run_scan()

    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    sqli_findings = [f for f in findings if f.type == "sqli"]
    assert len(sqli_findings) == 1
    # Must NOT produce NOT_DETECTED
    assert sqli_findings[0].status == "INCONCLUSIVE"
    assert "Inconclusive" in sqli_findings[0].title
    assert "0 candidate input parameters" in sqli_findings[0].evidence


# ==============================================================================
# CASE 2: Parameter actually tested with stable baseline and clean signal -> Not Detected
# ==============================================================================
@pytest.mark.asyncio
async def test_case_2_parameter_tested_with_stable_baseline_produces_truthful_not_detected(db_session):
    user = User(email=f"sqli_c2_{os.urandom(4).hex()}@test.com", password_hash="hash")
    db_session.add(user)
    db_session.commit()

    scan = Scan(
        user_id=user.id,
        target_url="https://clean-app.test/search?q=books",
        depth="standard",
        status="running",
        modules={"sqli": True}
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)
    endpoints = [{
        "url": "https://clean-app.test/search",
        "method": "GET",
        "params": ["q"],
        "param_values": {"q": "books"}
    }]
    forms = []

    # Clean web application responses: no errors, consistent DOM, fast response
    clean_resp = MockResponse(status_code=200, text="<html><body><h3>Search Results for books</h3></body></html>", duration=0.04)
    client = MockHTTPClient(default_response=clean_resp)

    coverage = await check_sqli(scanner, endpoints, forms, client, depth="standard")
    assert coverage.candidate_inputs_discovered == 1
    assert coverage.inputs_tested == 1
    assert "q" in coverage.tested_parameters
    assert coverage.requests_completed > 0
    assert coverage.baseline_stability == "stable"
    assert coverage.verification_completed is True

    # Test engine fallback logic
    with patch("scanner.checks.sqli.check_sqli", AsyncMock(return_value=coverage)):
        with patch("scanner.engine.SafeHTTPClient", return_value=client):
            with patch("scanner.engine.Crawler.run", AsyncMock(return_value={"urls": [scan.target_url], "endpoints": endpoints, "forms": forms})):
                await scanner.run_scan()

    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    sqli_findings = [f for f in findings if f.type == "sqli"]
    assert len(sqli_findings) == 1
    assert sqli_findings[0].status == "NOT_DETECTED"
    # Evidence must state actual parameters and request count, not generic boilerplate
    assert "Tested 1 parameter(s) (q)" in sqli_findings[0].evidence
    assert f"across {coverage.requests_completed} HTTP requests" in sqli_findings[0].evidence


# ==============================================================================
# CASE 3: Reproducible verified SQLi signal produces High severity
# ==============================================================================
@pytest.mark.asyncio
async def test_case_3_verified_sqli_signal_produces_high_severity(db_session):
    user = User(email=f"sqli_c3_{os.urandom(4).hex()}@test.com", password_hash="hash")
    db_session.add(user)
    db_session.commit()

    scan = Scan(
        user_id=user.id,
        target_url="https://vuln-app.test/items?category=Gifts",
        depth="standard",
        status="running",
        modules={"sqli": True}
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)
    endpoints = [{
        "url": "https://vuln-app.test/items",
        "method": "GET",
        "params": ["category"],
        "param_values": {"category": "Gifts"}
    }]

    def vuln_response_factory(method, url, kwargs):
        from urllib.parse import unquote
        parsed = urlparse(url)
        decoded = unquote(parsed.query)
        # If payload injected, return authentic PostgreSQL syntax error
        if "'" in decoded:
            return MockResponse(
                status_code=500,
                text="<html><body><h1>Server Error</h1><p>psycopg2.errors.SyntaxError: syntax error at or near \"'\"</p></body></html>"
            )
        return MockResponse(status_code=200, text="<html><body>Products list</body></html>")

    client = MockHTTPClient(response_factory=vuln_response_factory)
    coverage = await check_sqli(scanner, endpoints, [], client, depth="standard")

    assert coverage.inputs_tested == 1
    assert coverage.findings_added >= 1

    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.type == "sqli").all()
    confirmed = [f for f in findings if f.status in ("HIGH", "CRITICAL")]
    assert len(confirmed) >= 1
    assert confirmed[0].severity == "high"
    assert "syntax error at or near" in confirmed[0].evidence.lower()


# ==============================================================================
# CASE 4: Generic HTTP 500 alone does not confirm SQLi
# ==============================================================================
@pytest.mark.asyncio
async def test_case_4_generic_500_alone_does_not_confirm_sqli(db_session):
    user = User(email=f"sqli_c4_{os.urandom(4).hex()}@test.com", password_hash="hash")
    db_session.add(user)
    db_session.commit()

    scan = Scan(
        user_id=user.id,
        target_url="https://fragile-app.test/data?id=10",
        depth="standard",
        status="running",
        modules={"sqli": True}
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)
    endpoints = [{
        "url": "https://fragile-app.test/data",
        "method": "GET",
        "params": ["id"],
        "param_values": {"id": "10"}
    }]

    def generic_500_factory(method, url, kwargs):
        parsed = urlparse(url)
        # Return generic application error without database error signature
        if "'" in parsed.query:
            return MockResponse(
                status_code=500,
                text="<html><body><h1>500 Internal Server Error</h1><p>An internal error occurred.</p></body></html>"
            )
        return MockResponse(status_code=200, text="<html><body>Normal Data</body></html>")

    client = MockHTTPClient(response_factory=generic_500_factory)
    coverage = await check_sqli(scanner, endpoints, [], client, depth="standard")

    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id, Finding.type == "sqli").all()
    # Generic 500 must NOT produce confirmed HIGH severity SQLi
    high_findings = [f for f in findings if f.status in ("HIGH", "CRITICAL")]
    assert len(high_findings) == 0


# ==============================================================================
# CASE 5: Timing-check exception does not falsely report clean result
# ==============================================================================
@pytest.mark.asyncio
async def test_case_5_timing_check_exception_does_not_falsely_report_clean(db_session):
    user = User(email=f"sqli_c5_{os.urandom(4).hex()}@test.com", password_hash="hash")
    db_session.add(user)
    db_session.commit()

    scan = Scan(
        user_id=user.id,
        target_url="https://timing-flaky.test/page?user=test",
        depth="standard",
        status="running",
        modules={"sqli": True}
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)
    endpoints = [{
        "url": "https://timing-flaky.test/page",
        "method": "GET",
        "params": ["user"],
        "param_values": {"user": "test"}
    }]

    # Client raises runtime error during timing checks
    call_count = 0
    def flaky_factory(method, url, kwargs):
        nonlocal call_count
        call_count += 1
        if call_count > 4:
            raise ConnectionResetError("Connection dropped during timing probe")
        return MockResponse(status_code=200, text="<html><body>User profile</body></html>")

    client = MockHTTPClient(response_factory=flaky_factory)
    coverage = await check_sqli(scanner, endpoints, [], client, depth="deep")

    # Scanner error or inconclusive condition must be tracked
    assert coverage.scanner_error is not None or len(coverage.inconclusive_reasons) > 0


# ==============================================================================
# CASE 6: Scanner errors are represented as errors, not successful negative findings
# ==============================================================================
@pytest.mark.asyncio
async def test_case_6_scanner_errors_represented_as_errors_not_clean(db_session):
    user = User(email=f"sqli_c6_{os.urandom(4).hex()}@test.com", password_hash="hash")
    db_session.add(user)
    db_session.commit()

    scan = Scan(
        user_id=user.id,
        target_url="https://crashed.test/",
        depth="standard",
        status="running",
        modules={"sqli": True}
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)

    # Force check_sqli to raise an unhandled scanner exception
    with patch("scanner.checks.sqli.check_sqli", AsyncMock(side_effect=RuntimeError("Database driver aborted"))):
        with patch("scanner.engine.SafeHTTPClient"):
            with patch("scanner.engine.Crawler.run", AsyncMock(return_value={"urls": [scan.target_url], "endpoints": [], "forms": []})):
                await scanner.run_scan()

    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    sqli_findings = [f for f in findings if f.type == "sqli"]
    assert len(sqli_findings) == 1
    assert sqli_findings[0].status == "SCANNER_ERROR"
    assert "Scanner Error" in sqli_findings[0].title
    assert "Database driver aborted" in sqli_findings[0].evidence


# ==============================================================================
# CASE 7: SQLi and XSS coverage tracked independently
# ==============================================================================
@pytest.mark.asyncio
async def test_case_7_sqli_and_xss_coverage_tracked_independently(db_session):
    user = User(email=f"coverage_c7_{os.urandom(4).hex()}@test.com", password_hash="hash")
    db_session.add(user)
    db_session.commit()

    scan = Scan(
        user_id=user.id,
        target_url="https://independent.test/",
        depth="standard",
        status="running",
        modules={"sqli": True, "xss": True}
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)

    # Endpoints has 1 parameter for SQLi; forms is empty
    endpoints = [{
        "url": "https://independent.test/search",
        "method": "GET",
        "params": ["query"],
        "param_values": {"query": "sample"}
    }]
    forms = []

    clean_resp = MockResponse(status_code=200, text="<html><body>No results</body></html>")
    client = MockHTTPClient(default_response=clean_resp)

    # SQLi coverage has 1 candidate tested
    sqli_cov = SQLiCoverageRecord()
    sqli_cov.candidate_inputs_discovered = 1
    sqli_cov.inputs_tested = 1
    sqli_cov.requests_completed = 10
    sqli_cov.tested_parameters = ["query"]
    sqli_cov.baseline_stability = "stable"

    # XSS coverage had 0 inputs tested
    xss_cov = XSSCoverageRecord()
    xss_cov.candidate_inputs_discovered = 0
    xss_cov.inputs_tested = 0
    xss_cov.blocking_reason = "No candidate parameters discovered"

    with patch("scanner.checks.sqli.check_sqli", AsyncMock(return_value=sqli_cov)):
        with patch("scanner.checks.xss.check_xss", AsyncMock(return_value=xss_cov)):
            with patch("scanner.engine.SafeHTTPClient", return_value=client):
                with patch("scanner.engine.Crawler.run", AsyncMock(return_value={"urls": [scan.target_url], "endpoints": endpoints, "forms": forms})):
                    await scanner.run_scan()

    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    sqli_f = [f for f in findings if f.type == "sqli"][0]
    xss_f = [f for f in findings if f.type == "xss"][0]

    # SQLi had inputs tested -> NOT_DETECTED
    assert sqli_f.status == "NOT_DETECTED"
    # XSS had 0 inputs tested -> INCONCLUSIVE
    assert xss_f.status == "INCONCLUSIVE"


# ==============================================================================
# CASE 8: Insufficient coverage prevents security score of 100
# ==============================================================================
@pytest.mark.asyncio
async def test_case_8_insufficient_coverage_marks_score_unavailable(db_session):
    user = User(email=f"score_c8_{os.urandom(4).hex()}@test.com", password_hash="hash")
    db_session.add(user)
    db_session.commit()

    scan = Scan(
        user_id=user.id,
        target_url="https://empty-surface.test/",
        depth="standard",
        status="running",
        modules={"sqli": True, "xss": True}
    )
    db_session.add(scan)
    db_session.commit()

    scanner = SecurityScanner(db_session, scan.id)

    # Both active checks have 0 inputs discovered and tested
    sqli_cov = SQLiCoverageRecord()
    sqli_cov.candidate_inputs_discovered = 0
    sqli_cov.inputs_tested = 0

    xss_cov = XSSCoverageRecord()
    xss_cov.candidate_inputs_discovered = 0
    xss_cov.inputs_tested = 0

    with patch("scanner.checks.sqli.check_sqli", AsyncMock(return_value=sqli_cov)):
        with patch("scanner.checks.xss.check_xss", AsyncMock(return_value=xss_cov)):
            with patch("scanner.engine.SafeHTTPClient"):
                with patch("scanner.engine.Crawler.run", AsyncMock(return_value={"urls": [scan.target_url], "endpoints": [], "forms": []})):
                    await scanner.run_scan()

    db_session.refresh(scan)
    # When zero inputs were tested, score must NOT be 100!
    assert scan.security_score is None
    assert scan.status == "completed"


# ==============================================================================
# CASE 9: Executive summary truthfully reports coverage limitations
# ==============================================================================
@pytest.mark.asyncio
async def test_case_9_executive_summary_truthfully_reports_coverage_limitations(db_session):
    user = User(email=f"summary_c9_{os.urandom(4).hex()}@test.com", password_hash="hash")
    db_session.add(user)
    db_session.commit()

    scan = Scan(
        user_id=user.id,
        target_url="https://untested-target.test/",
        depth="standard",
        status="completed",
        security_score=None
    )
    db_session.add(scan)
    db_session.commit()

    # Findings: 2 inconclusive checks (SQLi & XSS with 0 tested inputs)
    f1 = Finding(
        scan_id=scan.id,
        type="sqli",
        severity="info",
        status="INCONCLUSIVE",
        title="SQL Injection Assessment Inconclusive (Untested Scope)",
        description="No inputs discovered",
        evidence="0 inputs tested"
    )
    f2 = Finding(
        scan_id=scan.id,
        type="xss",
        severity="info",
        status="INCONCLUSIVE",
        title="Cross-Site Scripting (XSS) Assessment Inconclusive (Untested Scope)",
        description="No inputs discovered",
        evidence="0 inputs tested"
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    findings = [f1, f2]
    counts = aggregate_finding_counts(findings)
    assert counts["inconclusive"] == 2
    assert counts["not_detected"] == 0
    assert counts["high"] == 0

    summary = await generate_executive_summary(scan, findings)
    overview = summary["security_overview"]

    # Must NOT claim target is clean or secure
    assert "Testing was inconclusive" in overview or "coverage limitations" in overview
    assert "All evaluated checks completed without detecting vulnerabilities" not in overview
    assert len(summary["scan_limitations"]) > 0
    assert any("untested" in act.lower() or "coverage" in act.lower() for act in summary["what_to_fix_first"])


# ==============================================================================
# CASE 10: Selected scan depth reaches runtime configuration and saved metadata
# ==============================================================================
def test_case_10_scan_depth_configuration_matches_runtime_and_database(db_session):
    # Test normalization of UI labels
    s1 = ScanCreate(target_id="tgt-1", depth="Deep Audit", authorized=True)
    assert s1.depth == "deep"

    s2 = ScanCreate(target_id="tgt-1", depth="deep scan", authorized=True)
    assert s2.depth == "deep"

    s3 = ScanCreate(target_id="tgt-1", depth="Standard Scan", authorized=True)
    assert s3.depth == "standard"

    s4 = ScanCreate(target_id="tgt-1", depth=None, authorized=True)
    assert s4.depth == "standard"

    # Invalid profile raises ValueError
    with pytest.raises(ValueError):
        ScanCreate(target_id="tgt-1", depth="ultra_aggressive", authorized=True)

    # Test Crawler depth parameterization
    client = MockHTTPClient()
    crawler_deep = Crawler("https://target.test", client, max_pages=50, max_depth=4)
    assert crawler_deep.max_depth == 4
    assert crawler_deep.max_pages == 50

    crawler_std = Crawler("https://target.test", client, max_pages=15, max_depth=2)
    assert crawler_std.max_depth == 2
    assert crawler_std.max_pages == 15
