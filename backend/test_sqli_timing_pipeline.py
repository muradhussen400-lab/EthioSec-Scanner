import pytest
import asyncio
import datetime
import os
import time
import httpx
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import unquote

os.environ["ALLOW_LOCAL_TARGETS"] = "true"

from scanner.checks.sqli import check_sqli, get_response_duration
from scanner.http_client import SafeHTTPClient
from scanner.differential import BaselineEngine, BaselineProfile
from scanner.test_case import TestCaseResult

class MockResponse:
    def __init__(self, status_code=200, text="Normal Page Content", headers=None, duration=0.05):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"Content-Type": "text/html"}
        self.duration = duration
        self._elapsed = datetime.timedelta(seconds=duration)

    @property
    def elapsed(self):
        return self._elapsed

class MockScanner:
    def __init__(self):
        self.findings = []
        self.cancelled = False
        self.scan_id = "test-scan-timing-001"
        self.target_id = "test-target-timing-001"
        self.db = None

    def _add_finding(self, f_type, severity, status, title, description, **kwargs):
        self.findings.append({
            "f_type": f_type,
            "severity": severity,
            "status": status,
            "title": title,
            "description": description,
            **kwargs
        })

class MockClient:
    def __init__(self):
        self.get = AsyncMock()
        self.post = AsyncMock()

# =============================================================================
# 1. Unread HTTPX Response .elapsed Access Safety
# =============================================================================
def test_unread_httpx_response_elapsed_access_safe():
    """
    Verifies that get_response_duration safely handles unread httpx.Response objects
    that would otherwise raise RuntimeError: '.elapsed' may only be accessed after
    the response has been read or closed.
    """
    # Raw httpx.Response constructed without setting _elapsed raises RuntimeError on .elapsed
    raw_response = httpx.Response(200, content=b"Unread content stream")
    with pytest.raises(RuntimeError, match=r"\.elapsed' may only be accessed after"):
        _ = raw_response.elapsed

    # Our safe helper extracts duration without raising any RuntimeError
    duration = get_response_duration(raw_response)
    assert isinstance(duration, float)
    assert duration >= 0.0

    # Verify duration extraction when duration attribute is explicitly set
    setattr(raw_response, "duration", 1.85)
    assert get_response_duration(raw_response) == 1.85

    # Verify duration extraction from _elapsed timedelta
    resp_with_elapsed = httpx.Response(200, content=b"Elapsed test")
    resp_with_elapsed.elapsed = datetime.timedelta(seconds=2.4)
    assert get_response_duration(resp_with_elapsed) == 2.4

# =============================================================================
# 2. SafeHTTPClient Sets elapsed and duration on Reconstructed Response
# =============================================================================
@pytest.mark.asyncio
async def test_safe_http_client_sets_elapsed_and_duration():
    """
    Verifies that SafeHTTPClient.request accurately records request-response cycle
    timing, setting both .elapsed (timedelta) and .duration (float) on the response.
    """
    async def sample_app(request):
        await asyncio.sleep(0.05)
        return httpx.Response(200, text="Completed with delay")

    mock_transport = httpx.MockTransport(sample_app)
    async with SafeHTTPClient() as client:
        client.client = httpx.AsyncClient(transport=mock_transport, follow_redirects=False)
        resp = await client.get("http://127.0.0.1:8000/test")
        
        assert resp is not None
        assert resp.status_code == 200
        assert hasattr(resp, "elapsed")
        assert isinstance(resp.elapsed, datetime.timedelta)
        assert resp.elapsed.total_seconds() >= 0.04
        assert hasattr(resp, "duration")
        assert isinstance(resp.duration, float)
        assert resp.duration >= 0.04

# =============================================================================
# 3. Timing: Reproducible Signal Confirmed as HIGH
# =============================================================================
@pytest.mark.asyncio
async def test_timing_reproducible_signal_confirmed():
    """
    Verifies that a reproducible, payload-specific delay (> 2.5s) with a prompt
    control (< 1.8s) correctly confirms Time-Based Blind SQL Injection (HIGH).
    """
    scanner = MockScanner()
    client = MockClient()

    def side_effect(url, **kwargs):
        decoded = unquote(url)
        # Injected sleep probes
        if "pg_sleep" in decoded or "SLEEP(" in decoded or "WAITFOR" in decoded:
            return MockResponse(200, "Catalog items", duration=3.0)
        # Baselines and prompt un-injected controls
        return MockResponse(200, "Catalog items", duration=0.05)
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://127.0.0.1:8000/items", "method": "GET", "params": ["cat"]}]
    await check_sqli(scanner, endpoints, [], client, depth="deep")

    assert len(scanner.findings) == 1
    finding = scanner.findings[0]
    assert finding["status"] == "HIGH"
    assert finding["confidence"] == "HIGH"
    assert "Time-Based Blind" in finding["title"] or "Time-Based Blind" in finding["description"]
    assert "3.0s" in finding["evidence"] or "time_delay" in finding["evidence"]

# =============================================================================
# 4. Timing: Slow Control Rejected as Server Congestion
# =============================================================================
@pytest.mark.asyncio
async def test_timing_slow_control_rejected_as_congestion():
    """
    Verifies that if the un-injected control request is ALSO slow (e.g. 2.8s),
    the delay is recognized as general server latency, preventing false confirmation.
    """
    scanner = MockScanner()
    client = MockClient()

    step = 0
    def side_effect(url, **kwargs):
        nonlocal step
        step += 1
        decoded = unquote(url)
        # Baselines: fast
        if step in (1, 2, 3):
            return MockResponse(200, "Catalog items", duration=0.05)
        # Probe takes 3.0s, but control request ALSO takes 2.9s due to server load
        if "pg_sleep" in decoded or "SLEEP(" in decoded:
            return MockResponse(200, "Catalog items", duration=3.0)
        return MockResponse(200, "Catalog items", duration=2.9)
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://127.0.0.1:8000/items", "method": "GET", "params": ["cat"]}]
    await check_sqli(scanner, endpoints, [], client, depth="deep")

    # Must NOT produce a HIGH confirmed finding
    high_findings = [f for f in scanner.findings if f.get("status") == "HIGH"]
    assert len(high_findings) == 0

# =============================================================================
# 5. Timing: Transient Delay Jitter Fails Verification
# =============================================================================
@pytest.mark.asyncio
async def test_timing_transient_spike_fails_verification():
    """
    Verifies that a one-off slow probe that does not reproduce on validation
    is flagged as jitter and not promoted to confirmed status.
    """
    scanner = MockScanner()
    client = MockClient()

    call_count = {"probe": 0}
    def side_effect(url, **kwargs):
        decoded = unquote(url)
        if "pg_sleep" in decoded or "SLEEP(" in decoded:
            call_count["probe"] += 1
            if call_count["probe"] == 1:
                return MockResponse(200, "Catalog items", duration=3.1)
            # Re-test fails to reproduce delay!
            return MockResponse(200, "Catalog items", duration=0.05)
        return MockResponse(200, "Catalog items", duration=0.05)
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://127.0.0.1:8000/items", "method": "GET", "params": ["cat"]}]
    await check_sqli(scanner, endpoints, [], client, depth="deep")

    # Must NOT confirm as HIGH
    high_findings = [f for f in scanner.findings if f.get("status") == "HIGH"]
    assert len(high_findings) == 0

# =============================================================================
# 6. Timing: HTTP 500 Server Error Delays Must Not Confirm SQLi
# =============================================================================
@pytest.mark.asyncio
async def test_timing_500_server_error_delays_rejected():
    """
    Verifies that an HTTP 500 error occurring after a delay (e.g. gateway timeout)
    is rejected and cannot confirm Time-Based SQL Injection.
    """
    scanner = MockScanner()
    client = MockClient()

    def side_effect(url, **kwargs):
        decoded = unquote(url)
        if "pg_sleep" in decoded or "SLEEP(" in decoded:
            return MockResponse(500, "500 Gateway Timeout / Error", duration=3.2)
        return MockResponse(200, "Catalog items", duration=0.05)
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://127.0.0.1:8000/items", "method": "GET", "params": ["cat"]}]
    await check_sqli(scanner, endpoints, [], client, depth="deep")

    # Must NOT confirm as HIGH
    high_findings = [f for f in scanner.findings if f.get("status") == "HIGH"]
    assert len(high_findings) == 0

# =============================================================================
# 7. Timing: Exception Isolation Preserves Engine Continuity
# =============================================================================
@pytest.mark.asyncio
async def test_timing_exception_isolation_preserves_continuity():
    """
    Verifies that an unexpected exception during timing probes (e.g. connection drop)
    is isolated, does not crash the scanner, and preserves other detected findings.
    """
    scanner = MockScanner()
    client = MockClient()

    def side_effect(url, **kwargs):
        decoded = unquote(url)
        # Controlled syntax probe triggers error-based SQLi
        if "'" in decoded and "pg_sleep" not in decoded and "SLEEP" not in decoded:
            return MockResponse(200, "you have an error in your sql syntax")
        # Timing probe raises unexpected exception
        if "pg_sleep" in decoded or "SLEEP" in decoded:
            raise RuntimeError("Unexpected socket drop during timing probe")
        return MockResponse(200, "Normal Page Content")
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://127.0.0.1:8000/items", "method": "GET", "params": ["id"]}]
    # Must complete safely without raising an unhandled exception
    await check_sqli(scanner, endpoints, [], client, depth="deep")

    # Error-based finding is preserved despite timing exception
    assert len(scanner.findings) == 1
    assert scanner.findings[0]["status"] == "HIGH"
    assert "Error-Based" in scanner.findings[0]["title"] or "MySQL" in scanner.findings[0]["evidence"]

# =============================================================================
# 8. Timing: Scan Cancellation Aborts Promptly
# =============================================================================
@pytest.mark.asyncio
async def test_timing_cancellation_aborts_promptly():
    """
    Verifies that when scanner.cancelled is set to True, timing tests abort
    promptly without burning request budgets.
    """
    scanner = MockScanner()
    client = MockClient()
    req_count = 0

    def side_effect(url, **kwargs):
        nonlocal req_count
        req_count += 1
        return MockResponse(200, "Normal Page Content", duration=0.05)
    client.get.side_effect = side_effect

    endpoints = [{"url": "http://127.0.0.1:8000/items", "method": "GET", "params": ["id"]}]
    scanner.cancelled = True
    await check_sqli(scanner, endpoints, [], client, depth="deep")

    # Aborts immediately on cancellation flag; 0 requests made
    assert req_count == 0
