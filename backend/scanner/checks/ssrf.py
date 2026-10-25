import logging
from typing import Dict, Any, List, Optional, TYPE_CHECKING
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

if TYPE_CHECKING:
    from scanner.engine import SecurityScanner

from scanner.http_client import SafeHTTPClient
from scanner.test_case import TestCaseResult
from models import Scan

logger = logging.getLogger("ethiosec.scanner.ssrf")

URL_CANDIDATE_PARAM_PATTERNS = [
    "url", "target", "dest", "destination", "redirect", "redirect_url", 
    "uri", "callback", "webhook", "feed", "proxy", "host", "domain", 
    "fetch", "load", "import", "endpoint", "path", "src", "link"
]


class SSRFCoverageRecord:
    def __init__(self):
        self.candidate_inputs_discovered: int = 0
        self.inputs_tested: int = 0
        self.findings_added: int = 0
        self.inconclusive_reasons: List[str] = []
        self.blocking_reason: Optional[str] = None
        self.verification_completed: bool = False


async def check_ssrf(
    scanner: "SecurityScanner",
    discovered_endpoints: list,
    discovered_forms: Any = None,
    client: Optional[SafeHTTPClient] = None,
    depth: str = "standard",
    *args, **kwargs
) -> SSRFCoverageRecord:
    """
    Safe, non-destructive Server-Side Request Forgery (SSRF) Audit Engine.
    STRICT SAFETY CONTROLS:
    - NEVER probes internal IP ranges (127.0.0.1, 10.0.0.0/8, 192.168.0.0/16, etc.) on external targets.
    - NEVER targets cloud metadata endpoints (169.254.169.254) or link-local subnets.
    - Evaluates URL parameter existence, scheme validation, and input sanitization safely.
    - Reports truthful coverage limitations when external out-of-band callbacks are not configured.
    """
    if client is None and discovered_forms is not None:
        # Caller called check_ssrf(scanner, endpoints, client)
        client = discovered_forms
        discovered_forms = []

    coverage = SSRFCoverageRecord()

    # Discover candidate URL parameters across GET endpoints
    candidate_params = []
    for ep in (discovered_endpoints or []):
        if isinstance(ep, dict):
            url = ep.get("url", "")
            method = ep.get("method", "GET").upper()
            raw_params = ep.get("params", [])
            param_values = ep.get("param_values", {})
        else:
            url = getattr(ep, "url", "")
            method = getattr(ep, "method", "GET").upper()
            raw_params = getattr(ep, "params", [])
            param_values = getattr(ep, "param_values", {})

        if isinstance(raw_params, dict):
            params = list(raw_params.keys())
            if not param_values:
                param_values = raw_params
        else:
            params = list(raw_params)

        for p in params:
            p_lower = str(p).lower()
            if any(cand == p_lower or p_lower.endswith(f"_{cand}") for cand in URL_CANDIDATE_PARAM_PATTERNS):
                candidate_params.append({
                    "url": url,
                    "method": method,
                    "parameter": p,
                    "default_value": param_values.get(p, "") if isinstance(param_values, dict) else "",
                    "source": "query"
                })

    # Discover candidate URL inputs in forms
    for form in (discovered_forms or []):
        action_url = form.get("action_url", "")
        method = form.get("method", "POST").upper()
        inputs = form.get("inputs", [])
        fields = form.get("fields", {})

        for inp in inputs:
            inp_lower = inp.lower()
            if any(cand == inp_lower or inp_lower.endswith(f"_{cand}") for cand in URL_CANDIDATE_PARAM_PATTERNS):
                val = fields.get(inp, {}).get("value", "") if isinstance(fields.get(inp), dict) else ""
                candidate_params.append({
                    "url": action_url,
                    "method": method,
                    "parameter": inp,
                    "default_value": val,
                    "source": "form"
                })

    coverage.candidate_inputs_discovered = len(candidate_params)

    if not candidate_params:
        coverage.blocking_reason = "No URL, webhook, or fetch-related parameters were discovered across the attack surface."
        coverage.verification_completed = True
        scanner._add_finding(
            f_type="ssrf",
            severity="info",
            status="NOT_DETECTED",
            title="No URL-Fetching Parameters Discovered",
            description="The crawler identified 0 URL or callback parameters (e.g. url, webhook, dest) across discovered endpoints. Safe SSRF protocol testing was not required.",
            evidence="Target exposed 0 candidate URL-fetch inputs.",
            url=getattr(scanner, "target_url", None) or (scanner.db.query(Scan).filter_by(id=scanner.scan_id).first().target_url if hasattr(scanner, "db") and scanner.db else None),
            owasp="A10:2021-Server-Side Request Forgery (SSRF)",
            cwe="CWE-918: Server-Side Request Forgery (SSRF)"
        )
        return coverage

    # Test scheme validation safely
    # We test whether the server enforces an HTTP/HTTPS allowlist or accepts arbitrary pseudo-protocols
    safe_scheme_probes = [
        ("file_scheme", "file:///invalid_safe_test_marker"),
        ("gopher_scheme", "gopher://invalid_safe_test_marker:70/"),
    ]

    for item in candidate_params:
        coverage.inputs_tested += 1
        url = item["url"]
        method = item["method"]
        param = item["parameter"]

        test_case = TestCaseResult(
            category="ssrf",
            target_endpoint=url,
            http_method=method,
            parameter=param,
            remediation=[
                "Implement strict allowlisting for allowed schemes (enforce https:// only).",
                "Validate destination IP addresses at connection time to block RFC 1918, loopback, and cloud metadata (169.254.169.254).",
                "Disable follow-redirects or re-validate redirect target URLs against the IP allowlist.",
                "Use an isolated egress proxy for external server-side requests."
            ],
            owasp="A10:2021-Server-Side Request Forgery (SSRF)",
            cwe="CWE-918: Server-Side Request Forgery (SSRF)"
        )

        # Baseline request
        try:
            if method == "GET":
                base_resp = await client.get(url)
            else:
                base_resp = await client.post(url, data={param: item["default_value"] or "https://example.com"})
        except Exception:
            base_resp = None

        if not base_resp:
            continue

        # Test protocol allowlist rejection
        unsupported_accepted = False
        tested_evidence = []
        for probe_name, probe_val in safe_scheme_probes:
            try:
                if method == "GET":
                    parsed = urlparse(url)
                    q_dict = dict(parse_qsl(parsed.query)) if parsed.query else {}
                    q_dict[param] = probe_val
                    full_test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(q_dict), parsed.fragment))
                    probe_resp = await client.get(full_test_url)
                else:
                    probe_resp = await client.post(url, data={param: probe_val})

                if probe_resp and probe_resp.status_code == 200:
                    # Check if the response indicates the server attempted to process the unsupported scheme
                    resp_lower = probe_resp.text.lower()
                    if any(indicator in resp_lower for indicator in ("file://", "gopher://", "unknown protocol", "scheme not supported")):
                        unsupported_accepted = True
                        tested_evidence.append(f"Server acknowledged '{probe_val}' with HTTP 200.")
            except Exception:
                pass

        if unsupported_accepted:
            test_case.add_observation(
                "unvalidated_scheme", 
                f"Parameter '{param}' accepts non-HTTP schemes ({', '.join(tested_evidence)}).",
                is_strong_evidence=True
            )
            test_case.severity = "medium"
            test_case.evaluate()

            coverage.findings_added += 1
            scanner._add_finding(
                f_type="ssrf",
                severity="medium",
                status="MEDIUM",
                title=f"Potential SSRF: Unvalidated URL Parameter '{param}'",
                description=f"Endpoint accepts URL parameters without strict scheme validation. If passed to server-side fetch libraries, this can allow access to unauthorized destinations.",
                evidence=test_case.evidence,
                impact="Attackers may abuse unvalidated URL parameters to interact with internal services or trigger unintended server-side network requests.",
                remediation=test_case.remediation,
                owasp=test_case.owasp,
                cwe=getattr(test_case, "cwe", None) or "CWE-918: Server-Side Request Forgery (SSRF)",
                url=url,
                parameter=param,
                http_method=method
            )
        else:
            test_case.add_observation(
                "safe_scheme_rejected", 
                f"Parameter '{param}' correctly rejected invalid and non-HTTP scheme probes.",
                is_suspicious=False
            )

    coverage.inconclusive_reasons.append(
        "Out-of-band SSRF callback verification was not executed because no controlled external callback listener was configured for this scan. Internal/metadata probing was safely skipped to prevent unauthorized access."
    )
    coverage.verification_completed = True
    return coverage
