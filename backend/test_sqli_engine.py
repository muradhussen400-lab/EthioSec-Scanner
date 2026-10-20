import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import unquote
from scanner.checks.sqli import check_sqli
from scanner.engine import SecurityScanner
from scanner.http_client import SafeHTTPClient
from scanner.test_case import TestCaseResult
from typing import Optional

class MockResponse:
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"Content-Type": "text/html"}

class MockClient:
    def __init__(self):
        self.get = AsyncMock()
        self.post = AsyncMock()

@pytest.fixture
def mock_scanner():
    scanner = MagicMock(spec=SecurityScanner)
    scanner._add_finding = MagicMock()
    return scanner

@pytest.fixture
def mock_client():
    return MockClient()

@pytest.mark.asyncio
async def test_normal_parameter_not_detected(mock_scanner, mock_client):
    mock_client.get.return_value = MockResponse(200, "Normal Page Content")
    endpoints = [{"url": "http://test.com", "method": "GET", "params": ["id"]}]
    await check_sqli(mock_scanner, endpoints, [], mock_client)
    mock_scanner._add_finding.assert_not_called()

@pytest.mark.asyncio
async def test_normal_500_not_sqli(mock_scanner, mock_client):
    # Baseline 200, test payloads all return generic 500
    responses = [MockResponse(200, "Normal Page Content"), MockResponse(200, "Normal Page Content")] # baselines
    for _ in range(20):
        responses.append(MockResponse(500, "Internal Server Error"))
    mock_client.get.side_effect = responses
    
    endpoints = [{"url": "http://test.com", "method": "GET", "params": ["id"]}]
    await check_sqli(mock_scanner, endpoints, [], mock_client)
    mock_scanner._add_finding.assert_not_called()

@pytest.mark.asyncio
async def test_db_error_after_controlled_input(mock_scanner, mock_client):
    # Baseline 200, one payload causes DB error, validation succeeds
    def side_effect(url, **kwargs):
        url = unquote(url)
        if "'" in url:
            return MockResponse(200, "you have an error in your sql syntax")
        return MockResponse(200, "Normal Page Content")
    
    mock_client.get.side_effect = side_effect
    endpoints = [{"url": "http://test.com", "method": "GET", "params": ["id"]}]
    await check_sqli(mock_scanner, endpoints, [], mock_client)
    mock_scanner._add_finding.assert_called_once()
    args, kwargs = mock_scanner._add_finding.call_args
    assert kwargs["status"] == "HIGH"

@pytest.mark.asyncio
async def test_stable_true_false_differential(mock_scanner, mock_client):
    def side_effect(url, **kwargs):
        url = unquote(url)
        if "1=2" in url:
            return MockResponse(200, "No results found. " + "0" * 100)
        return MockResponse(200, "Normal Page Content") # normal and true payload
        
    mock_client.get.side_effect = side_effect
    endpoints = [{"url": "http://test.com", "method": "GET", "params": ["id"]}]
    await check_sqli(mock_scanner, endpoints, [], mock_client)
    mock_scanner._add_finding.assert_called_once()
    args, kwargs = mock_scanner._add_finding.call_args
    assert kwargs["status"] == "HIGH"

@pytest.mark.asyncio
async def test_unstable_true_false(mock_scanner, mock_client):
    # Baseline unstable on its own
    mock_client.get.side_effect = [
        MockResponse(200, "Normal Page Content 1"),
        MockResponse(200, "Normal Page Content 2"),
        MockResponse(200, "True payload"),
        MockResponse(200, "False payload"),
        MockResponse(200, "True payload validate 1"),
        MockResponse(200, "False payload validate 2"),
    ]
    
    endpoints = [{"url": "http://test.com", "method": "GET", "params": ["id"]}]
    await check_sqli(mock_scanner, endpoints, [], mock_client)
    # The boolean differential should fail to find stability
    mock_scanner._add_finding.assert_not_called()

@pytest.mark.asyncio
async def test_baseline_already_contains_db_error(mock_scanner, mock_client):
    mock_client.get.return_value = MockResponse(200, "you have an error in your sql syntax baseline")
    endpoints = [{"url": "http://test.com", "method": "GET", "params": ["id"]}]
    await check_sqli(mock_scanner, endpoints, [], mock_client)
    # Shouldn't trigger finding based on error since baseline has it
    mock_scanner._add_finding.assert_not_called()

@pytest.mark.asyncio
async def test_repeated_validation_fails(mock_scanner, mock_client):
    # First time DB error, second time no error
    responses = [
        MockResponse(200, "Normal Page"), # baseline 1
        MockResponse(200, "Normal Page"), # baseline 2
        MockResponse(200, "you have an error in your sql syntax"), # syntax payload 1
        MockResponse(200, "Normal Page") # validation fails
    ]
    # remaining payloads
    responses.extend([MockResponse(200, "Normal Page") for _ in range(20)])
    
    def side_effect(*args, **kwargs):
        if responses:
            return responses.pop(0)
        return MockResponse(200, "Normal Page")
        
    mock_client.get.side_effect = side_effect
    endpoints = [{"url": "http://test.com", "method": "GET", "params": ["id"]}]
    await check_sqli(mock_scanner, endpoints, [], mock_client)
    mock_scanner._add_finding.assert_called_once()
    args, kwargs = mock_scanner._add_finding.call_args
    assert kwargs["status"] == "LOW"

@pytest.mark.asyncio
async def test_scanner_network_error(mock_scanner, mock_client):
    mock_client.get.side_effect = Exception("Network timeout")
    endpoints = [{"url": "http://test.com", "method": "GET", "params": ["id"]}]
    await check_sqli(mock_scanner, endpoints, [], mock_client)
    mock_scanner._add_finding.assert_not_called()

@pytest.mark.asyncio
async def test_correct_evidence_attached(mock_scanner, mock_client):
    def side_effect(url, **kwargs):
        url = unquote(url)
        if "'" in url and "1=2" not in url and "1=1" not in url:
            return MockResponse(200, "syntax error at or near")
        return MockResponse(200, "Normal Page Content")
    
    mock_client.get.side_effect = side_effect
    endpoints = [{"url": "http://test.com", "method": "GET", "params": ["id"]}]
    await check_sqli(mock_scanner, endpoints, [], mock_client)
    
    mock_scanner._add_finding.assert_called_once()
    args, kwargs = mock_scanner._add_finding.call_args
    
    assert "syntax error at or near" in kwargs["evidence"]
    assert "PostgreSQL" in kwargs["evidence"] or "PostgreSQL" in kwargs["description"]
    assert "{'id': " in kwargs["request"] # Ensure request shows the test param
    assert "id" in kwargs["parameter"]

# --- Additional Scenarios ---

@pytest.mark.asyncio
async def test_scenario_a_normal_search_parameter(mock_scanner, mock_client):
    # Scenario A: Normal search parameter where TRUE/FALSE inputs naturally return different pages.
    # The application reflects the input.
    # ?q=test -> "results for test"
    # ?q=test' OR 1=1-- -> "results for test' OR 1=1--"
    def side_effect(url, **kwargs):
        url = unquote(url)
        return MockResponse(200, f"results for {url.split('=')[-1]} and some padding to exceed length diff check if needed. We need to make sure the length difference is less than 5% or 50 bytes so it doesn't fail similarity, OR if it does fail similarity, then TRUE payload will fail similarity with Baseline, and thus not trigger Boolean SQLi.")
        
    mock_client.get.side_effect = side_effect
    endpoints = [{"url": "http://test.com", "method": "GET", "params": ["q"]}]
    await check_sqli(mock_scanner, endpoints, [], mock_client)
    mock_scanner._add_finding.assert_not_called()

@pytest.mark.asyncio
async def test_scenario_b_dynamic_page(mock_scanner, mock_client):
    # Scenario B: Dynamic page where every request has changing content (length changes > 5% / > 50 bytes).
    call_count = 0
    def side_effect(url, **kwargs):
        nonlocal call_count
        call_count += 1
        padding = "X" * (1000 * call_count)
        return MockResponse(200, f"Dynamic content {padding}")
        
    mock_client.get.side_effect = side_effect
    endpoints = [{"url": "http://test.com", "method": "GET", "params": ["id"]}]
    await check_sqli(mock_scanner, endpoints, [], mock_client)
    if mock_scanner._add_finding.called:
        args, kwargs = mock_scanner._add_finding.call_args
        assert kwargs.get('status') == 'LOW'

@pytest.mark.asyncio
async def test_scenario_c_baseline_has_db_error(mock_scanner, mock_client):
    # Scenario C: Baseline already contains a database error.
    mock_client.get.return_value = MockResponse(200, "you have an error in your sql syntax")
    endpoints = [{"url": "http://test.com", "method": "GET", "params": ["id"]}]
    await check_sqli(mock_scanner, endpoints, [], mock_client)
    mock_scanner._add_finding.assert_not_called()

@pytest.mark.asyncio
async def test_scenario_e_suspicious_diff_disappears(mock_scanner, mock_client):
    # Scenario E: A suspicious differential appears once but disappears during validation.
    call_count = {"1=1": 0, "1=2": 0}
    def side_effect(url, **kwargs):
        url = unquote(url)
        if "1=1" in url:
            call_count["1=1"] += 1
            return MockResponse(200, "Normal Page Content")
        elif "1=2" in url:
            call_count["1=2"] += 1
            if call_count["1=2"] == 1:
                return MockResponse(200, "Different Page Content" + "Y"*100)
            else:
                return MockResponse(200, "Normal Page Content")
        return MockResponse(200, "Normal Page Content")
        
    mock_client.get.side_effect = side_effect
    endpoints = [{"url": "http://test.com", "method": "GET", "params": ["id"]}]
    await check_sqli(mock_scanner, endpoints, [], mock_client)
    mock_scanner._add_finding.assert_called_once()
    args, kwargs = mock_scanner._add_finding.call_args
    assert kwargs["status"] == "LOW"

@pytest.mark.asyncio
async def test_scenario_f_http_500_for_every_request(mock_scanner, mock_client):
    # Scenario F: HTTP 500 occurs for every request.
    mock_client.get.return_value = MockResponse(500, "Internal Server Error")
    endpoints = [{"url": "http://test.com", "method": "GET", "params": ["id"]}]
    await check_sqli(mock_scanner, endpoints, [], mock_client)
    mock_scanner._add_finding.assert_not_called()

@pytest.mark.asyncio
async def test_scenario_h_evidence_comes_from_payload_x(mock_scanner, mock_client):
    # Scenario H: Evidence comes from payload X, but later payload Y is executed.
    def side_effect(url, **kwargs):
        url = unquote(url)
        # Payload X = ' triggers DB error.
        # Payload Y = ';-- is executed later, but doesn't trigger error because vulnerable=True breaks loop.
        if url.endswith("'"):
            return MockResponse(200, "you have an error in your sql syntax")
        return MockResponse(200, "Normal Page Content")
        
    mock_client.get.side_effect = side_effect
    endpoints = [{"url": "http://test.com", "method": "GET", "params": ["id"]}]
    await check_sqli(mock_scanner, endpoints, [], mock_client)
    
    mock_scanner._add_finding.assert_called_once()
    args, kwargs = mock_scanner._add_finding.call_args
    assert kwargs["status"] == "HIGH"
    # Ensure evidence shows the exact payload
    assert "{'id': " in kwargs["request"]
    assert "test'" in kwargs["request"] # NOT test';--
