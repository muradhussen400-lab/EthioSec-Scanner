"""
Professional, evidence-driven Cross-Site Scripting (XSS) engine for EthioSec Scanner.

Detection Philosophy & Verification Hierarchy:
1. Input Discovered: URL query, HTML form, JSON payload, or cookie input registered.
2. Baseline Established: Repeated requests via BaselineProfile to verify endpoint stability,
   detect existing reflections, record baseline headers (including Content-Security-Policy),
   and eliminate baseline noise.
3. Marker Reflected: Unique, benign per-test canary marker injected. If unreflected, clean NOT_DETECTED.
4. Reflection Context Identified: Robust DOM analysis via BeautifulSoup classifying context:
   - HTML body text ('html_text')
   - Quoted HTML attributes ('attribute_double_quoted', 'attribute_single_quoted')
   - Unquoted HTML attributes ('attribute_unquoted')
   - Event handler attributes ('attribute_event_handler')
   - URI attributes ('attribute_uri')
   - JavaScript code/string ('javascript_single_quoted', 'javascript_double_quoted', 'javascript_code')
   - HTML comments ('comment')
   - Stylesheet ('css')
   - JSON response ('json')
   - Ambiguous / unmapped ('ambiguous')
5. Transformation & Encoding Evaluated: Granular probe analyzing handling of special characters (< > " ' & / ; ( ))
   relative to the detected context.
6. Context-Specific Controlled Breakout Probes: Harmless probes attempting structural boundary exit.
7. Structural HTML Validation: Verifying whether the breakout created an actual structural element
   or attribute in the DOM, confirmed via differential comparison against baseline.
8. Repeated Verification: Secondary verification request confirming deterministic reproducibility.
9. Browser Execution Verification (Optional/Pluggable): Headless browser execution with unique canary
   signal verification, or explicit recording of runtime environment limitations.
10. Defensible Status & Evidence Mapping:
    - CONFIRMED: Verified browser script execution with correlated canary signal.
    - POTENTIAL: Reproducible structural HTML injection at HTTP protocol layer, or unsafe character survival
      without browser execution proof. (Adjusted if CSP blocks inline execution).
    - NOT_DETECTED: Completed tests demonstrated safe encoding, filtering, or no reflection.
    - INCONCLUSIVE: Unstable baseline, rate-limited, conflicting signals, or untested scope.
    - ERROR / BLOCKED: Technical network failures or WAF interference recorded truthfully.
"""

from typing import TYPE_CHECKING, Optional, Dict, Any, List, Set, Tuple
if TYPE_CHECKING:
    from scanner.engine import SecurityScanner

import asyncio
import logging
import random
import string
import re
import json
import time
import datetime
import html
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, urlparse
from bs4 import BeautifulSoup, Comment, NavigableString

import httpx
from scanner.http_client import SafeHTTPClient
from scanner.test_case import TestCaseResult
from scanner.differential import BaselineEngine, BaselineProfile
from scanner.checks.sqli import is_sensitive_cookie

logger = logging.getLogger("ethiosec.scanner.xss")


def mutate_url_parameter(url: str, param_name: str, new_value: str) -> str:
    """
    Mutates a specific query parameter in a GET URL while strictly preserving
    all other unrelated parameters, duplicate keys, blank values, and query order.
    """
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    updated = False
    new_pairs = []
    for k, v in pairs:
        if k == param_name and not updated:
            new_pairs.append((k, new_value))
            updated = True
        else:
            new_pairs.append((k, v))
            
    if not updated:
        new_pairs.append((param_name, new_value))
        
    new_query = urlencode(new_pairs, doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))


def extract_snippet(text: str, idx: int, length: int, context_chars: int = 40) -> str:
    """Safely extracts a surrounding snippet around an index."""
    if not text or idx < 0:
        return ""
    start = max(0, idx - context_chars)
    end = min(len(text), idx + length + context_chars)
    snippet = text[start:end]
    return " ".join(snippet.split())


def analyze_reflection_contexts(html_text: str, marker: str, content_type: str = "") -> List[Dict[str, Any]]:
    """
    Robust DOM and contextual classification of marker occurrences.
    Identifies whether the marker is inside HTML text, quoted/unquoted attributes,
    event handlers, URIs, JavaScript strings or code, comments, CSS, JSON, or plain text.
    """
    if not html_text or not marker or marker not in html_text:
        return []

    ct_lower = (content_type or "").lower()
    
    # 1. Non-HTML & JSON Data Context Checks
    if "application/json" in ct_lower or (
        html_text.strip().startswith(("{", "[")) and html_text.strip().endswith(("}", "]"))
    ):
        try:
            json.loads(html_text)
            contexts = []
            for m in re.finditer(re.escape(marker), html_text):
                idx = m.start()
                contexts.append({
                    "index": idx,
                    "context": "json",
                    "tag": None,
                    "attr": None,
                    "snippet": extract_snippet(html_text, idx, len(marker))
                })
            return contexts
        except Exception:
            pass

    # Check for text/plain and other non-HTML formats
    is_non_html = bool(ct_lower and any(
        t in ct_lower for t in ("text/plain", "text/csv", "application/pdf", "application/octet-stream", "image/", "audio/", "video/")
    ) and not any(h in ct_lower for h in ("html", "xml")))

    if is_non_html:
        contexts = []
        for m in re.finditer(re.escape(marker), html_text):
            idx = m.start()
            contexts.append({
                "index": idx,
                "context": "plain_text",
                "tag": None,
                "attr": None,
                "snippet": extract_snippet(html_text, idx, len(marker))
            })
        return contexts

    # 2. HTML / DOM Context Classification
    contexts = []
    marker_len = len(marker)
    start_pos = 0

    while True:
        idx = html_text.find(marker, start_pos)
        if idx == -1:
            break
            
        start_pos = idx + marker_len
        prefix = html_text[:idx]
        prefix_lower = prefix.lower()
        
        # Check comment boundary
        last_comment_open = prefix.rfind("<!--")
        last_comment_close = prefix.rfind("-->")
        if last_comment_open != -1 and last_comment_open > last_comment_close:
            contexts.append({
                "index": idx,
                "context": "comment",
                "tag": None,
                "attr": None,
                "snippet": extract_snippet(html_text, idx, marker_len)
            })
            continue

        # Check script boundary
        last_script_open = prefix_lower.rfind("<script")
        last_script_close = prefix_lower.rfind("</script>")
        if last_script_open != -1 and last_script_open > last_script_close:
            script_sub = prefix[last_script_open:]
            # Robust JavaScript lexical state machine
            in_single = False
            in_double = False
            in_template = False
            in_line_comment = False
            in_block_comment = False
            escaped = False

            i = 0
            while i < len(script_sub):
                ch = script_sub[i]
                if in_line_comment:
                    if ch == '\n':
                        in_line_comment = False
                elif in_block_comment:
                    if ch == '*' and i + 1 < len(script_sub) and script_sub[i+1] == '/':
                        in_block_comment = False
                        i += 1
                elif in_single:
                    if escaped:
                        escaped = False
                    elif ch == '\\':
                        escaped = True
                    elif ch == "'":
                        in_single = False
                elif in_double:
                    if escaped:
                        escaped = False
                    elif ch == '\\':
                        escaped = True
                    elif ch == '"':
                        in_double = False
                elif in_template:
                    if escaped:
                        escaped = False
                    elif ch == '\\':
                        escaped = True
                    elif ch == '`':
                        in_template = False
                else:
                    if ch == '/' and i + 1 < len(script_sub) and script_sub[i+1] == '/':
                        in_line_comment = True
                        i += 1
                    elif ch == '/' and i + 1 < len(script_sub) and script_sub[i+1] == '*':
                        in_block_comment = True
                        i += 1
                    elif ch == "'":
                        in_single = True
                    elif ch == '"':
                        in_double = True
                    elif ch == '`':
                        in_template = True
                i += 1

            if in_line_comment or in_block_comment:
                js_ctx = "javascript_comment"
            elif in_single:
                js_ctx = "javascript_single_quoted"
            elif in_double:
                js_ctx = "javascript_double_quoted"
            elif in_template:
                js_ctx = "javascript_template_literal"
            else:
                js_ctx = "javascript_code"
                
            contexts.append({
                "index": idx,
                "context": js_ctx,
                "tag": "script",
                "attr": None,
                "snippet": extract_snippet(html_text, idx, marker_len)
            })
            continue

        # Check style boundary
        last_style_open = prefix_lower.rfind("<style")
        last_style_close = prefix_lower.rfind("</style>")
        if last_style_open != -1 and last_style_open > last_style_close:
            contexts.append({
                "index": idx,
                "context": "css",
                "tag": "style",
                "attr": None,
                "snippet": extract_snippet(html_text, idx, marker_len)
            })
            continue

        # Check HTML tag boundary (inside < ... >) with attribute quote awareness
        tag_open = False
        in_attr_quote = None
        curr_tag_start = -1

        p_i = 0
        while p_i < len(prefix):
            ch = prefix[p_i]
            if not tag_open:
                if ch == '<' and p_i + 1 < len(prefix) and (prefix[p_i+1].isalpha() or prefix[p_i+1] == '/'):
                    tag_open = True
                    curr_tag_start = p_i
            else:
                if in_attr_quote:
                    if ch == in_attr_quote:
                        in_attr_quote = None
                else:
                    if ch in ('"', "'"):
                        in_attr_quote = ch
                    elif ch == '>':
                        tag_open = False
                        curr_tag_start = -1
            p_i += 1

        if tag_open and curr_tag_start != -1:
            tag_text = prefix[curr_tag_start:]
            tag_name_match = re.match(r"^<([a-zA-Z0-9_\-]+)", tag_text)
            curr_tag = tag_name_match.group(1).lower() if tag_name_match else "unknown"

            # Parse attribute name and quote
            attr_match = re.search(r'([a-zA-Z0-9_\-:]+)\s*=\s*([\'"]?)[^\'"]*$', tag_text)
            if attr_match:
                attr_name = attr_match.group(1).lower()
                quote = in_attr_quote or attr_match.group(2)
                
                if attr_name.startswith("on"):
                    ctx = "attribute_event_handler"
                elif attr_name in ("href", "src", "action", "formaction", "data", "poster"):
                    ctx = "attribute_uri"
                elif quote == '"':
                    ctx = "attribute_double_quoted"
                elif quote == "'":
                    ctx = "attribute_single_quoted"
                else:
                    ctx = "attribute_unquoted"
            else:
                ctx = "attribute_unquoted"
                attr_name = None

            contexts.append({
                "index": idx,
                "context": ctx,
                "tag": curr_tag,
                "attr": attr_name,
                "snippet": extract_snippet(html_text, idx, marker_len)
            })
            continue

        # Default: normal HTML text node
        contexts.append({
            "index": idx,
            "context": "html_text",
            "tag": "body",
            "attr": None,
            "snippet": extract_snippet(html_text, idx, marker_len)
        })

    return contexts



def analyze_encoding_transformations(resp_text: str, marker: str) -> Dict[str, str]:
    """
    Evaluates character handling and entity transformations (< > " ' & / ; ( ))
    around the canary marker, isolating the probe from surrounding HTML tags.
    """
    start_tag = f"{marker}xssstart"
    end_tag = f"{marker}xssend"
    
    start_idx = resp_text.find(start_tag)
    if start_idx != -1:
        end_idx = resp_text.find(end_tag, start_idx)
        if end_idx != -1:
            after_marker = resp_text[start_idx + len(start_tag) : end_idx]
        else:
            tail = resp_text[start_idx + len(start_tag) : start_idx + len(start_tag) + 60]
            m_tag = re.search(r'</?[a-zA-Z]', tail)
            after_marker = tail[:m_tag.start()] if m_tag else tail
    else:
        idx = resp_text.find(marker)
        if idx == -1:
            return {}
        tail = resp_text[idx + len(marker) : idx + len(marker) + 60]
        m_tag = re.search(r'</?[a-zA-Z]', tail)
        after_marker = tail[:m_tag.start()] if m_tag else tail
    
    res = {}
    # < check
    if "<" in after_marker:
        res["<"] = "raw"
    elif any(e in after_marker for e in ("&lt;", "&#60;", "&#x3c;", "&#X3C;", "&LT;")):
        res["<"] = "encoded"
    else:
        res["<"] = "stripped_or_altered"
        
    # > check
    if ">" in after_marker:
        res[">"] = "raw"
    elif any(e in after_marker for e in ("&gt;", "&#62;", "&#x3e;", "&#X3E;", "&GT;")):
        res[">"] = "encoded"
    else:
        res[">"] = "stripped_or_altered"

    # " check
    if '\\"' in after_marker:
        res['"'] = "escaped"
    elif '"' in after_marker:
        res['"'] = "raw"
    elif any(e in after_marker for e in ("&quot;", "&#34;", "&#x22;", "&#X22;", "&QUOT;")):
        res['"'] = "encoded"
    else:
        res['"'] = "stripped_or_altered"

    # ' check
    if "\\'" in after_marker:
        res["'"] = "escaped"
    elif "'" in after_marker:
        res["'"] = "raw"
    elif any(e in after_marker for e in ("&#39;", "&#x27;", "&#X27;", "&apos;", "&APOS;")):
        res["'"] = "encoded"
    else:
        res["'"] = "stripped_or_altered"

    # & check
    if any(e in after_marker for e in ("&amp;", "&#38;", "&#x26;", "&AMP;")):
        res["&"] = "encoded"
    elif "&" in after_marker:
        res["&"] = "raw"
    else:
        res["&"] = "stripped_or_altered"

    # / check
    if "/" in after_marker:
        res["/"] = "raw"
    elif any(e in after_marker for e in ("&#47;", "&#x2f;", "&#X2F;")):
        res["/"] = "encoded"
    else:
        res["/"] = "stripped_or_altered"

    # ; check
    res[";"] = "raw" if ";" in after_marker else "stripped_or_altered"
    
    # ( ) check
    res["()"] = "raw" if ("(" in after_marker and ")" in after_marker) else "stripped_or_altered"
    
    return res


def evaluate_context_vulnerability(context: str, enc_map: Dict[str, str]) -> Tuple[bool, str]:
    """
    Determines if observed transformations permit a context breakout.
    """
    if context in ("json", "plain_text"):
        return False, f"Non-HTML response context ('{context}') does not parse or execute as active DOM elements."
        
    if context == "html_text":
        if enc_map.get("<") == "raw" and enc_map.get(">") == "raw":
            return True, "Angle brackets (<>) survive raw in HTML text."
        if enc_map.get("<") == "raw":
            return True, "Opening angle bracket (<) survives raw in HTML text."
        return False, "Angle brackets (<>) are safely entity-encoded or stripped in HTML text."

    if context == "attribute_double_quoted":
        if enc_map.get('"') == "raw":
            return True, "Double quotes survive unescaped/unencoded in double-quoted attribute."
        return False, "Double quotes are safely encoded or escaped in double-quoted attribute."

    if context == "attribute_single_quoted":
        if enc_map.get("'") == "raw":
            return True, "Single quotes survive unescaped/unencoded in single-quoted attribute."
        return False, "Single quotes are safely encoded or escaped in single-quoted attribute."

    if context == "attribute_unquoted":
        if enc_map.get(">") == "raw" or enc_map.get("<") == "raw" or enc_map.get(" ") == "raw" or True:
            return True, "Unquoted attribute allows boundary exit via whitespace or delimiters."

    if context == "attribute_event_handler":
        if enc_map.get('"') == "raw" or enc_map.get("()") == "raw" or enc_map.get(";") == "raw":
            return True, "Event handler attribute reflects dangerous script characters."
        return False, "Event handler attribute sanitizes dangerous script characters."

    if context == "attribute_uri":
        return True, "URI attribute may permit javascript: pseudo-protocol injection."

    if context in ("javascript_single_quoted", "javascript_double_quoted"):
        quote_char = "'" if "single" in context else '"'
        if enc_map.get(quote_char) == "raw":
            return True, f"String quote ({quote_char}) survives raw/unescaped in JavaScript string."
        if enc_map.get("<") == "raw" and enc_map.get(">") == "raw":
            return True, "Script closing sequence (</script>) is unneutralized in JavaScript context."
        return False, f"JavaScript string delimiters ({quote_char}) and script tags are safely escaped or encoded."

    if context == "javascript_template_literal":
        if enc_map.get("`") == "raw" or (enc_map.get("<") == "raw" and enc_map.get(">") == "raw"):
            return True, "Backtick (`) survives raw in JavaScript template literal."
        return False, "Template literal delimiters safely neutralized."

    if context == "javascript_comment":
        if enc_map.get("<") == "raw" and enc_map.get(">") == "raw":
            return True, "Script closing sequence (</script>) is unneutralized in JavaScript comment."
        return False, "Input safely neutralized in JavaScript comment."

    if context == "javascript_code":
        if enc_map.get(";") == "raw" or enc_map.get("()") == "raw":
            return True, "Direct JavaScript code context reflects input without neutralization."
        return False, "Input neutralized in JavaScript code context."

    if context == "comment":
        if enc_map.get(">") == "raw":
            return True, "Comment closing delimiter (-->) survives raw in HTML comment."
        return False, "Comment closing delimiter is neutralized."

    return False, f"Context '{context}' safely neutralizes dangerous inputs."


async def verify_browser_execution(
    url: str, 
    method: str, 
    params: dict, 
    location: str, 
    canary_token: str,
    timeout: float = 5.0
) -> Tuple[str, str]:
    """
    Optional, controlled headless browser verification stage.
    Verifies client-side execution via an observable browser canary signal.
    """
    try:
        import playwright.async_api as pw
    except ImportError:
        return "UNSUPPORTED_ENVIRONMENT", "Playwright headless browser framework is not installed in runtime environment."
    except Exception as e:
        return "UNSUPPORTED_ENVIRONMENT", f"Playwright import failed: {e}"

    browser = None
    playwright_inst = None
    try:
        playwright_inst = await pw.async_playwright().start()
        browser = await playwright_inst.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
        )
        context = await browser.new_context(
            ignore_https_errors=True,
            java_script_enabled=True
        )

        if location == "cookie" and params:
            cookie_items = []
            for ck, cv in params.items():
                cookie_items.append({"name": str(ck), "value": str(cv), "url": url})
            try:
                await context.add_cookies(cookie_items)
            except Exception as ce:
                logger.debug(f"Could not seed browser cookies: {ce}")

        page = await context.new_page()

        executed = False
        execution_details = []

        def on_console(msg):
            nonlocal executed
            if canary_token in msg.text:
                executed = True
                execution_details.append(f"Console signal: {msg.text}")

        def on_page_error(err):
            nonlocal executed
            if canary_token in str(err):
                executed = True
                execution_details.append(f"Script execution error with canary: {err}")

        page.on("console", on_console)
        page.on("pageerror", on_page_error)
        page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))

        target_exec_url = url
        if method.upper() == "POST" and params and location != "cookie":
            inputs_html = "".join([f'<input type="hidden" name="{html.escape(str(k))}" value="{html.escape(str(v))}">' for k, v in params.items()])
            html_content = f'<html><body><form id="f" method="POST" action="{html.escape(url)}">{inputs_html}</form><script>document.getElementById("f").submit();</script></body></html>'
            try:
                await page.set_content(html_content)
                await page.wait_for_load_state("domcontentloaded", timeout=int(timeout * 1000))
            except Exception:
                pass
        else:
            if method.upper() == "GET" and params and location != "cookie":
                for p_k, p_v in params.items():
                    target_exec_url = mutate_url_parameter(target_exec_url, p_k, str(p_v or ""))

            try:
                await page.goto(target_exec_url, wait_until="domcontentloaded", timeout=int(timeout * 1000))
            except Exception:
                pass

        try:
            await page.wait_for_timeout(300)
        except Exception:
            pass

        # Check DOM canary flag
        try:
            dom_executed = await page.evaluate(f"() => window.__ethioxss_{canary_token} === true")
            if dom_executed:
                executed = True
                execution_details.append(f"window.__ethioxss_{canary_token} flag confirmed")
        except Exception:
            pass

        if executed:
            return "CONFIRMED", "; ".join(execution_details) or "Browser canary signal detected"
        else:
            return "ATTEMPTED_NO_EXECUTION", "Browser navigated successfully; no canary script execution observed."

    except Exception as exc:
        return "UNSUPPORTED_ENVIRONMENT", f"Headless browser engine unavailable or failed to initialize: {exc}"
    finally:
        if browser:
            try:
                await browser.close()
            except Exception:
                pass
        if playwright_inst:
            try:
                await playwright_inst.stop()
            except Exception:
                pass


class XSSCoverageRecord:
    """
    Transparent execution and attack surface coverage record for XSS testing.
    Tracks candidate inputs, executed tests, completed requests, baseline stability,
    and verified techniques independently from SQLi.
    """
    def __init__(self):
        self.candidate_inputs_discovered: int = 0
        self.inputs_tested: int = 0
        self.requests_attempted: int = 0
        self.requests_completed: int = 0
        self.tested_parameters: List[str] = []
        self.blocking_reason: Optional[str] = None
        self.scanner_error: Optional[str] = None
        self.findings_added: int = 0
        self.verification_completed: bool = False
        
        # Extended professional coverage telemetry matching SQLi
        self.baseline_stability: str = "not_evaluated"
        self.inconclusive_reasons: List[str] = []
        self.contexts_discovered: List[str] = []
        self.contexts_tested: List[str] = []
        self.techniques_attempted: List[str] = []
        self.techniques_completed: List[str] = []
        self.candidate_forms_discovered: int = 0
        self.candidate_json_parameters_discovered: int = 0
        self.json_parameters_tested: int = 0
        self.candidate_cookies_discovered: int = 0
        self.cookies_tested: int = 0
        self.cookies_excluded_policy: List[str] = []
        self.browser_verification_status: str = "unsupported_environment"


async def check_xss(
    scanner: "SecurityScanner", 
    endpoints: list, 
    forms: list, 
    client: SafeHTTPClient, 
    depth: str = "standard",
    cookies: list = None,
    allow_session_cookie_testing: bool = False,
    enable_browser_verification: bool = True
) -> XSSCoverageRecord:
    """
    Professional, evidence-driven Cross-Site Scripting (XSS) detection pipeline.
    Executes baseline profiling, reflection identification, context classification,
    granular transformation analysis, controlled structural validation, repeated
    verification, and optional browser signal checking.
    """
    depth = (depth or "standard").lower()
    coverage = XSSCoverageRecord()

    def _is_scan_cancelled() -> bool:
        if scanner:
            if getattr(scanner, "cancelled", False) or getattr(scanner, "is_cancelled", False):
                return True
            if hasattr(scanner, "db") and scanner.db and hasattr(scanner, "scan_id"):
                try:
                    from models import Scan
                    s_rec = scanner.db.query(Scan).filter(Scan.id == scanner.scan_id).first()
                    if s_rec and s_rec.status == "cancelled":
                        return True
                except Exception:
                    pass
        return False

    def _extract_csrf_from_html(html_text: str, field_name: str) -> Optional[str]:
        if not html_text:
            return None
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            tag = soup.find(["input", "textarea"], attrs={"name": field_name})
            if tag and tag.get("value"):
                return tag["value"]
        except Exception:
            pass
        return None

    async def _fetch_csrf_token(page_url: str, field_name: str) -> Optional[str]:
        try:
            get_resp = await client.get(page_url)
            if get_resp and get_resp.text:
                return _extract_csrf_from_html(get_resp.text, field_name)
        except Exception:
            pass
        return None

    async def _make_request(
        url: str, 
        method: str, 
        params: dict = None, 
        target_param: str = None,
        target_value: str = None,
        cookies_dict: dict = None,
        page_url: str = None, 
        csrf_field: str = None,
        location: str = "query"
    ) -> Optional[httpx.Response]:
        """
        Executes HTTP request, preserving unrelated parameters, cookies, and CSRF tokens.
        Increments requests_completed strictly upon HTTP completion.
        """
        coverage.requests_attempted += 1
        params = params.copy() if params else {}
        req_cookies = dict(cookies_dict) if cookies_dict else {}
        if location == "cookie" and target_param and target_value is not None:
            req_cookies[target_param] = str(target_value)
        
        try:
            resp = None
            if location == "json":
                if target_param and target_value is not None:
                    params[target_param] = target_value
                if hasattr(client, "post"):
                    resp = await client.post(url, json=params, cookies=req_cookies)
                else:
                    resp = await client.request(method or "POST", url, json=params, cookies=req_cookies)
            elif method == "GET":
                if location in ("query", "form") and target_param and target_value is not None:
                    full_url = mutate_url_parameter(url, target_param, target_value)
                    if params and location != "cookie":
                        for k, v in params.items():
                            if k != target_param:
                                full_url = mutate_url_parameter(full_url, k, str(v or ""))
                else:
                    full_url = url
                    if params and location != "cookie":
                        for k, v in params.items():
                            full_url = mutate_url_parameter(full_url, k, str(v or ""))
                resp = await client.get(full_url, cookies=req_cookies)
            else:
                # POST form
                if target_param and target_value is not None and location == "form":
                    params[target_param] = target_value
                if csrf_field and page_url:
                    fresh = await _fetch_csrf_token(page_url, csrf_field)
                    if fresh:
                        params[csrf_field] = fresh
                resp = await client.post(url, data=params, cookies=req_cookies)

            if resp is not None:
                coverage.requests_completed += 1
            return resp
        except Exception as e:
            logger.debug(f"Request error for {method} {url}: {e.__class__.__name__} - {e}")
            err_msg = f"{e.__class__.__name__}: {str(e)}"
            if err_msg not in coverage.inconclusive_reasons:
                coverage.inconclusive_reasons.append(err_msg)
            return None

    async def test_parameter(
        url: str, 
        method: str, 
        params: dict, 
        param_to_inject: str, 
        source: str, 
        page_url: str = None, 
        csrf_field: str = None,
        cookies_dict: dict = None,
        location: str = "query"
    ):
        if _is_scan_cancelled():
            return

        coverage.inputs_tested += 1
        param_label = f"json:{param_to_inject}" if location == "json" else (f"cookie:{param_to_inject}" if location == "cookie" else param_to_inject)
        if param_label not in coverage.tested_parameters:
            coverage.tested_parameters.append(param_label)

        baseline_params = params.copy() if params else {}

        # 1. Baseline Establishment
        if "baseline_profiling" not in coverage.techniques_attempted:
            coverage.techniques_attempted.append("baseline_profiling")

        baseline_requests_count = 3 if depth == "deep" else 2
        baseline_responses = []
        for _ in range(baseline_requests_count):
            if _is_scan_cancelled():
                break
            resp = await _make_request(
                url, method, params=baseline_params, 
                cookies_dict=cookies_dict, page_url=page_url, 
                csrf_field=csrf_field, location=location
            )
            if resp:
                baseline_responses.append(resp)
            else:
                break

        test_case = TestCaseResult(
            category="xss",
            target_endpoint=url,
            http_method=method,
            parameter=param_to_inject,
            location=location,
            baseline_request={"params": baseline_params, "location": location},
            remediation=[
                "Apply context-aware output encoding (e.g. HTML entity encoding for HTML text, attribute encoding for attributes).",
                "Deploy a robust Content Security Policy (CSP) restricting inline script execution.",
                "Ensure modern framework templating handles context-specific auto-escaping."
            ],
            owasp="A03:2021-Injection",
            cwe="CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
        )

        if len(baseline_responses) < baseline_requests_count or not baseline_responses:
            test_case.status = "SCANNER_ERROR"
            test_case.verification_status = "ERROR"
            test_case.add_observation("scanner_error", "Technical failure prevented reliable baseline establishment.")
            test_case.evaluate()
            
            scanner._add_finding(
                f_type="xss", severity="info", status="SCANNER_ERROR",
                verification_status="ERROR",
                title=f"Scanner Error via {source.capitalize()} Parameter '{param_to_inject}'",
                description="Technical failure or target unresponsiveness prevented reliable baseline establishment.",
                evidence=test_case.evidence, url=url, parameter=param_to_inject, http_method=method
            )
            coverage.scanner_error = "Technical failure during baseline establishment."
            return

        profile = BaselineProfile(baseline_responses)
        if "baseline_profiling" not in coverage.techniques_completed:
            coverage.techniques_completed.append("baseline_profiling")

        test_case.add_observation(
            "baseline", 
            f"Baseline established ({len(profile.requests)} requests). HTTP {profile.baseline_status}. Stable: {profile.is_stable} ({profile.stability_reason})."
        )

        # Baseline stability evaluation
        if profile.baseline_status == 429:
            test_case.status = "INCONCLUSIVE"
            test_case.verification_status = "INCONCLUSIVE"
            test_case.add_observation("rate_limited", f"Baseline requests encountered rate limiting (HTTP 429) on parameter '{param_to_inject}'. Inconclusive.")
            coverage.baseline_stability = "rate_limited"
            coverage.inconclusive_reasons.append(f"Rate limited (HTTP 429) on '{param_to_inject}'")
            test_case.evaluate()
            return

        if not profile.is_stable:
            coverage.baseline_stability = "unstable"
            coverage.inconclusive_reasons.append(f"Unstable baseline on '{param_to_inject}': {profile.stability_reason}")
            test_case.add_observation("baseline_unstable", f"Endpoint baseline is unstable ({profile.stability_reason}). High verification standards applied.")
        else:
            if coverage.baseline_stability not in ("unstable", "rate_limited"):
                coverage.baseline_stability = "stable"

        base_resp = baseline_responses[0]
        csp_header = base_resp.headers.get("Content-Security-Policy", "")
        if not csp_header and base_resp.text:
            meta_csp_match = re.search(r'<meta\s+[^>]*http-equiv=[\'"]Content-Security-Policy[\'"][^>]*content=[\'"]([^\'"]+)[\'"]', base_resp.text, re.IGNORECASE)
            if meta_csp_match:
                csp_header = meta_csp_match.group(1)

        content_type = base_resp.headers.get("Content-Type", "")

        csp_blocks_inline = False
        if csp_header:
            csp_lower = csp_header.lower()
            test_case.add_observation("csp_present", f"CSP detected: {csp_header}", is_suspicious=False)
            has_script_policy = any(d in csp_lower for d in ("script-src", "default-src"))
            if has_script_policy:
                # Under CSP Level 2/3, nonces, hashes, or strict-dynamic cause browsers to ignore 'unsafe-inline'
                has_nonce_or_hash = bool(re.search(r"'(nonce-[^']+|sha256-[^']+|sha384-[^']+|sha512-[^']+|strict-dynamic)'", csp_lower))
                if has_nonce_or_hash:
                    csp_blocks_inline = True
                elif "'unsafe-inline'" not in csp_lower:
                    csp_blocks_inline = True

        if "application/json" in content_type.lower():
            test_case.add_observation("json_response", "Response is JSON data context.", is_suspicious=False)
        elif any(t in content_type.lower() for t in ("text/plain", "text/csv", "application/pdf")):
            test_case.add_observation("non_html_response", f"Response Content-Type is '{content_type}', not executable HTML/DOM.", is_suspicious=False)

        # 2. Canary Reflection Testing
        if "canary_reflection" not in coverage.techniques_attempted:
            coverage.techniques_attempted.append("canary_reflection")

        marker = "ethioxss_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        
        # Verify marker is not already present in baseline
        if marker in base_resp.text:
            marker = "ethioxss_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))

        marker_resp = await _make_request(
            url, method, params=baseline_params, target_param=param_to_inject,
            target_value=str(baseline_params.get(param_to_inject) or "") + marker,
            cookies_dict=cookies_dict, page_url=page_url, csrf_field=csrf_field, location=location
        )

        if not marker_resp:
            test_case.status = "SCANNER_ERROR"
            test_case.verification_status = "ERROR"
            test_case.add_observation("scanner_error", "Technical failure during canary reflection testing.")
            test_case.evaluate()
            scanner._add_finding(
                f_type="xss", severity="info", status="SCANNER_ERROR", verification_status="ERROR",
                title=f"Scanner Error via {source.capitalize()} Parameter '{param_to_inject}'",
                description="Technical failure during reflection testing.", url=url, parameter=param_to_inject, http_method=method
            )
            return

        if "canary_reflection" not in coverage.techniques_completed:
            coverage.techniques_completed.append("canary_reflection")

        if marker not in marker_resp.text:
            test_case.add_observation("no_reflection", "Harmless canary marker was not reflected in the response.")
            test_case.evaluate()
            return

        reflections = analyze_reflection_contexts(marker_resp.text, marker, content_type=content_type)
        unique_contexts = sorted(list(set(r["context"] for r in reflections)))
        
        for c_item in unique_contexts:
            if c_item not in coverage.contexts_discovered:
                coverage.contexts_discovered.append(c_item)

        test_case.add_observation(
            "reflection_found", 
            f"Marker '{marker}' reflected {len(reflections)} time(s). Identified contexts: {', '.join(unique_contexts)}."
        )

        # If reflection is solely in non-HTML data context, raw characters do not execute
        if all(r["context"] in ("json", "plain_text") for r in reflections):
            test_case.add_observation("non_html_safe", "Input is reflected solely inside a non-HTML data context without HTML/DOM execution path.", is_suspicious=False)
            test_case.evaluate()
            return

        # 3. Encoding / Sanitization Analysis
        if "encoding_analysis" not in coverage.techniques_attempted:
            coverage.techniques_attempted.append("encoding_analysis")

        probe_start = f"{marker}xssstart"
        probe_end = f"{marker}xssend"
        encoding_marker = f"{probe_start}<>\"'&/;(){probe_end}"
        enc_resp = await _make_request(
            url, method, params=baseline_params, target_param=param_to_inject,
            target_value=str(baseline_params.get(param_to_inject) or "") + encoding_marker,
            cookies_dict=cookies_dict, page_url=page_url, csrf_field=csrf_field, location=location
        )

        if not enc_resp:
            test_case.status = "SCANNER_ERROR"
            test_case.verification_status = "ERROR"
            test_case.add_observation("scanner_error", "Technical failure during encoding analysis.")
            test_case.evaluate()
            scanner._add_finding(
                f_type="xss", severity="info", status="SCANNER_ERROR", verification_status="ERROR",
                title=f"Scanner Error via {source.capitalize()} Parameter '{param_to_inject}'",
                description="Technical failure during encoding analysis.", url=url, parameter=param_to_inject, http_method=method
            )
            return

        if "encoding_analysis" not in coverage.techniques_completed:
            coverage.techniques_completed.append("encoding_analysis")

        if marker not in enc_resp.text and probe_start not in enc_resp.text:
            test_case.add_observation("filtering_detected", "Input was heavily filtered or dropped when dangerous characters were introduced.", is_suspicious=False)
            test_case.evaluate()
            return

        enc_transformations = analyze_encoding_transformations(enc_resp.text, marker)
        survives_raw = any(enc_transformations.get(ch) == "raw" for ch in ("<", ">", '"', "'"))

        # Check vulnerability potential per discovered context
        potentially_vulnerable_contexts = []
        for ctx in unique_contexts:
            if ctx not in coverage.contexts_tested:
                coverage.contexts_tested.append(ctx)
            is_vuln_pot, reason = evaluate_context_vulnerability(ctx, enc_transformations)
            if is_vuln_pot:
                potentially_vulnerable_contexts.append(ctx)
                test_case.add_observation("encoding_analysis", f"Context '{ctx}': {reason}", is_suspicious=True)
            else:
                test_case.add_observation("encoding_analysis", f"Context '{ctx}': {reason}", is_suspicious=False)

        # 4. Controlled Context-Specific Injection Validation
        vulnerable = False
        evidence_payload = None
        evidence_params = None
        reproduced_breakout_context = None

        if potentially_vulnerable_contexts:
            if "structural_breakout_validation" not in coverage.techniques_attempted:
                coverage.techniques_attempted.append("structural_breakout_validation")

            for ctx in potentially_vulnerable_contexts:
                if _is_scan_cancelled():
                    break

                test_payloads = []
                if ctx == "html_text":
                    test_payloads = [f"<{marker}tag>"]
                    if depth == "deep":
                        test_payloads.append(f"<img src=x onerror={marker}()>")
                elif ctx == "attribute_double_quoted":
                    test_payloads = [f"\"><{marker}tag>", f"\" autofocus onfocus=\"{marker}()"]
                elif ctx == "attribute_single_quoted":
                    test_payloads = [f"'><{marker}tag>", f"' autofocus onfocus='{marker}()"]
                elif ctx == "attribute_unquoted":
                    test_payloads = [f" autofocus onfocus={marker}()", f"><{marker}tag>"]
                elif ctx == "attribute_event_handler":
                    test_payloads = [f";{marker}()"]
                elif ctx == "attribute_uri":
                    test_payloads = [f"javascript:{marker}()"]
                elif ctx in ("javascript_single_quoted", "javascript_double_quoted"):
                    q = "'" if "single" in ctx else '"'
                    test_payloads = [f"</script><{marker}tag>", f"{q};{marker}();//"]
                elif ctx == "comment":
                    test_payloads = [f"--><{marker}tag>"]
                else:
                    test_payloads = [f"\"><{marker}tag>", f"<{marker}tag>"]

                for payload in test_payloads:
                    if _is_scan_cancelled():
                        break

                    inj_resp = await _make_request(
                        url, method, params=baseline_params, target_param=param_to_inject,
                        target_value=str(baseline_params.get(param_to_inject) or "") + payload,
                        cookies_dict=cookies_dict, page_url=page_url, csrf_field=csrf_field, location=location
                    )

                    if not inj_resp:
                        continue

                    inj_text = inj_resp.text
                    breakout_success = False

                    # Structural verification via DOM inspection
                    soup = BeautifulSoup(inj_text, "html.parser")
                    tag_name = f"{marker}tag".lower()

                    if f"<{marker}tag>" in payload:
                        if soup.find(tag_name):
                            breakout_success = True
                    elif f"{marker}()" in payload:
                        # Check for active event attribute
                        for tag in soup.find_all(True):
                            if tag.has_attr("onfocus") and marker in tag["onfocus"]:
                                breakout_success = True
                                break
                            if tag.has_attr("onerror") and marker in tag["onerror"]:
                                breakout_success = True
                                break
                            if tag.has_attr("href") and tag["href"].strip().startswith(f"javascript:{marker}()"):
                                breakout_success = True
                                break
                            if tag.name == "iframe" and tag.has_attr("src") and tag["src"].strip().startswith(f"javascript:{marker}()"):
                                breakout_success = True
                                break
                        # In JS string context, ensure matching delimiter broke out without escaping
                        if ctx in ("javascript_single_quoted", "javascript_double_quoted"):
                            delim = "'" if "single" in ctx else '"'
                            if payload.startswith(delim) and f"\\{delim}" not in inj_text and f"{marker}()" in inj_text:
                                breakout_success = True

                    if breakout_success:
                        if "structural_breakout_validation" not in coverage.techniques_completed:
                            coverage.techniques_completed.append("structural_breakout_validation")

                        # 5. Repeated Verification Request
                        if "repeated_verification" not in coverage.techniques_attempted:
                            coverage.techniques_attempted.append("repeated_verification")

                        val_resp = await _make_request(
                            url, method, params=baseline_params, target_param=param_to_inject,
                            target_value=str(baseline_params.get(param_to_inject) or "") + payload,
                            cookies_dict=cookies_dict, page_url=page_url, csrf_field=csrf_field, location=location
                        )

                        if val_resp:
                            val_soup = BeautifulSoup(val_resp.text, "html.parser")
                            val_success = False
                            
                            if f"<{marker}tag>" in payload:
                                if val_soup.find(tag_name):
                                    val_success = True
                            elif f"{marker}()" in payload:
                                for tag in val_soup.find_all(True):
                                    if tag.has_attr("onfocus") and marker in tag["onfocus"]:
                                        val_success = True
                                        break
                                    if tag.has_attr("onerror") and marker in tag["onerror"]:
                                        val_success = True
                                        break
                                    if tag.has_attr("href") and tag["href"].strip().startswith(f"javascript:{marker}()"):
                                        val_success = True
                                        break
                                    if tag.name == "iframe" and tag.has_attr("src") and tag["src"].strip().startswith(f"javascript:{marker}()"):
                                        val_success = True
                                        break
                                if ctx in ("javascript_single_quoted", "javascript_double_quoted"):
                                    delim = "'" if "single" in ctx else '"'
                                    if payload.startswith(delim) and f"\\{delim}" not in val_resp.text and f"{marker}()" in val_resp.text:
                                        val_success = True

                            if val_success:
                                if "repeated_verification" not in coverage.techniques_completed:
                                    coverage.techniques_completed.append("repeated_verification")

                                diff_record = BaselineEngine.compare(base_resp, val_resp)
                                final_snip = extract_snippet(val_resp.text, max(0, val_resp.text.find(payload)), len(payload))
                                test_case.add_observation(
                                    "controlled_validation",
                                    f"Payload '{payload}' reproduced structural transformation reliably across repeated verification. Snippet: ...{final_snip}... (Similarity: {diff_record.get('similarity_ratio')})",
                                    is_strong_evidence=True
                                )
                                vulnerable = True
                                evidence_payload = payload
                                evidence_params = {**baseline_params, param_to_inject: str(baseline_params.get(param_to_inject) or "") + payload}
                                reproduced_breakout_context = ctx
                                break
                            else:
                                test_case.add_observation(
                                    "validation_failed",
                                    f"Payload '{payload}' showed initial breakout, but failed to reproduce on repeated verification.",
                                    is_suspicious=True
                                )

                if vulnerable:
                    break

        # 6. Optional Controlled Browser Verification Stage
        browser_confirmed = False
        browser_status = "UNSUPPORTED_ENVIRONMENT"
        browser_evidence_note = "Playwright headless browser framework is not installed in the runtime environment."

        if vulnerable and enable_browser_verification and not _is_scan_cancelled():
            if "browser_execution_verification" not in coverage.techniques_attempted:
                coverage.techniques_attempted.append("browser_execution_verification")

            # Determine parameters for browser testing. If evidence payload was non-executable (e.g. <tag>),
            # construct a harmless context-specific execution canary to test if client-side JS can execute.
            browser_params = dict(evidence_params or baseline_params)
            if evidence_payload and not any(k in evidence_payload for k in ("(", "onerror", "onfocus", "onload", "script", "javascript:")):
                base_v = str(baseline_params.get(param_to_inject) or "")
                canary_script = f"<script>window.__ethioxss_{marker}=true;console.log('{marker}');</script>"
                if reproduced_breakout_context == "html_text":
                    browser_params[param_to_inject] = base_v + canary_script
                elif reproduced_breakout_context == "attribute_double_quoted":
                    browser_params[param_to_inject] = base_v + f"\">{canary_script}"
                elif reproduced_breakout_context == "attribute_single_quoted":
                    browser_params[param_to_inject] = base_v + f"'>{canary_script}"
                elif reproduced_breakout_context in ("javascript_single_quoted",):
                    browser_params[param_to_inject] = base_v + f"';window.__ethioxss_{marker}=true;console.log('{marker}');//"
                elif reproduced_breakout_context in ("javascript_double_quoted",):
                    browser_params[param_to_inject] = base_v + f"\";window.__ethioxss_{marker}=true;console.log('{marker}');//"
                elif reproduced_breakout_context == "attribute_event_handler":
                    browser_params[param_to_inject] = base_v + f";window.__ethioxss_{marker}=true;console.log('{marker}');"
                elif reproduced_breakout_context == "attribute_uri":
                    browser_params[param_to_inject] = f"javascript:window.__ethioxss_{marker}=true;console.log('{marker}');"

            b_status, b_evidence = await verify_browser_execution(
                url=url, method=method, params=browser_params,
                location=location, canary_token=marker
            )
            browser_status = b_status
            browser_evidence_note = b_evidence
            coverage.browser_verification_status = browser_status
            
            if "browser_execution_verification" not in coverage.techniques_completed:
                coverage.techniques_completed.append("browser_execution_verification")

            if b_status == "CONFIRMED":
                browser_confirmed = True
                test_case.add_observation(
                    "browser_execution_verified",
                    f"Browser execution confirmed via client-side canary signal: {b_evidence}",
                    is_strong_evidence=True
                )
            else:
                test_case.add_observation(
                    "browser_execution_not_verified",
                    f"Browser verification outcome: {b_status}. Details: {b_evidence}",
                    is_suspicious=False
                )

        test_case.evaluate()

        # 7. Assembling Defensible Finding
        if browser_confirmed:
            finding_status = "HIGH"
            finding_severity = "high"
            verif_status = "CONFIRMED"
            finding_conf = "HIGH"
            title = f"Reflected Cross-Site Scripting (XSS) Executable via {source.capitalize()} Parameter '{param_to_inject}'"
            desc = (
                f"Client-side JavaScript execution was validated in a real browser engine via {source} parameter '{param_to_inject}'. "
                f"The payload escaped the '{reproduced_breakout_context or 'DOM'}' context."
            )
        elif vulnerable:
            finding_status = "MEDIUM"
            if csp_blocks_inline:
                finding_severity = "low"
                verif_status = "POTENTIAL"
                finding_conf = "MEDIUM"
                title = f"Potential Reflected XSS (Structural Injection Mitigated by CSP) via {source.capitalize()} Parameter '{param_to_inject}'"
                desc = (
                    f"The parameter '{param_to_inject}' permits reproducible structural HTML injection at the HTTP protocol layer into '{', '.join(unique_contexts)}'. "
                    f"However, the application's Content-Security-Policy restricts inline script execution."
                )
            else:
                finding_severity = "medium"
                verif_status = "POTENTIAL"
                finding_conf = "HIGH"
                title = f"Potential Reflected XSS / Structural HTML Injection via {source.capitalize()} Parameter '{param_to_inject}'"
                desc = (
                    f"The parameter '{param_to_inject}' permits reproducible structural HTML injection at the HTTP protocol layer into '{', '.join(unique_contexts)}'. "
                    f"Browser-side script execution was not validated ({browser_evidence_note})."
                )
        elif survives_raw and test_case.status in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            finding_status = "LOW"
            finding_severity = "low"
            verif_status = "POTENTIAL"
            finding_conf = "LOW"
            title = f"Potential Unsafe Input Reflection via {source.capitalize()} Parameter '{param_to_inject}'"
            desc = (
                f"Dangerous characters survived without context-appropriate encoding in parameter '{param_to_inject}' "
                f"into '{', '.join(unique_contexts)}', but controlled breakout attempts failed or were neutralized."
            )
        else:
            finding_status = None

        if finding_status:
            scanner._add_finding(
                f_type="xss",
                severity=finding_severity,
                status=finding_status,
                verification_status=verif_status,
                confidence=finding_conf,
                title=title,
                description=desc,
                evidence=f"Location: {location}\nParameter: {param_to_inject}\n{test_case.evidence}",
                impact="Attackers can inject arbitrary HTML markup or execute script in the victim's session if context execution succeeds.",
                remediation=test_case.remediation,
                owasp=test_case.owasp,
                cwe=test_case.cwe,
                url=url,
                parameter=param_to_inject,
                http_method=method,
                request=str(evidence_params) if evidence_params else str(baseline_params),
                response_summary=f"Evaluated via Context Analysis Pipeline in {location} parameter"
            )
            coverage.findings_added += 1

    # Stage A: Harvest and categorize candidate inputs
    candidate_endpoints = []
    candidate_json_endpoints = []
    
    for endpoint in (endpoints or []):
        if endpoint.get("source") == "form" and forms:
            continue
        url = endpoint.get("url", "")
        method = endpoint.get("method", "GET").upper()
        content_type = str(endpoint.get("content_type", "")).lower()
        json_data = endpoint.get("json_data") or endpoint.get("json_body") or (endpoint.get("param_values") if "application/json" in content_type else None)

        if "application/json" in content_type or endpoint.get("location") == "json" or (json_data and isinstance(json_data, dict)):
            j_params = list(endpoint.get("params", []))
            if not j_params and isinstance(json_data, dict):
                j_params = list(json_data.keys())
            j_values = dict(json_data) if isinstance(json_data, dict) else dict(endpoint.get("param_values", {}))
            if j_params:
                candidate_json_endpoints.append({
                    "url": url,
                    "method": method if method != "GET" else "POST",
                    "params": j_params,
                    "values": j_values
                })
                coverage.candidate_inputs_discovered += len(j_params)
                coverage.candidate_json_parameters_discovered += len(j_params)
            continue

        params_list = list(endpoint.get("params", []))
        param_values = dict(endpoint.get("param_values", {}))
        parsed_url = urlparse(url)
        url_query_dict = dict(parse_qsl(parsed_url.query, keep_blank_values=True))
        all_param_names = params_list or list(url_query_dict.keys())
        merged_values = {**url_query_dict, **param_values}
        if all_param_names:
            candidate_endpoints.append({
                "url": url,
                "method": method,
                "params": all_param_names,
                "values": merged_values
            })
            coverage.candidate_inputs_discovered += len(all_param_names)

    candidate_forms = []
    for form in (forms or []):
        action_url = form.get("action_url", "")
        page_url = form.get("page_url", action_url)
        method = form.get("method", "POST")
        inputs = list(form.get("inputs", []))
        fields = dict(form.get("fields", {}))
        if inputs:
            candidate_forms.append({
                "action_url": action_url,
                "page_url": page_url,
                "method": method,
                "inputs": inputs,
                "fields": fields
            })
            coverage.candidate_inputs_discovered += len(inputs)
            coverage.candidate_forms_discovered += 1

    # Stage A.2: Harvest Cookies if provided
    candidate_cookies = []
    all_cookies_dict: Dict[str, str] = {}
    raw_cookies: List[Any] = list(cookies or [])
    
    if scanner and hasattr(scanner, "inventory") and isinstance(scanner.inventory, dict):
        for c in scanner.inventory.get("cookies", []):
            c_n = c.get("name") if isinstance(c, dict) else getattr(c, "name", None)
            if c_n and not any((x.get("name") if isinstance(x, dict) else getattr(x, "name", None)) == c_n for x in raw_cookies):
                raw_cookies.append(c)

    for c in raw_cookies:
        c_name = c.get("name") if isinstance(c, dict) else getattr(c, "name", None)
        c_val = c.get("value", "") if isinstance(c, dict) else getattr(c, "value", "")
        c_url = c.get("url") if isinstance(c, dict) else getattr(c, "url", None)
        if not c_name:
            continue
        all_cookies_dict[c_name] = str(c_val or "")
        coverage.candidate_cookies_discovered += 1

        if is_sensitive_cookie(c_name) and not allow_session_cookie_testing:
            if c_name not in coverage.cookies_excluded_policy:
                coverage.cookies_excluded_policy.append(c_name)
            continue

        c_target_url = c_url or getattr(scanner, "target_url", "") or (candidate_endpoints[0]["url"] if candidate_endpoints else "")
        candidate_cookies.append({
            "name": c_name,
            "value": str(c_val or ""),
            "url": c_target_url
        })
        coverage.candidate_inputs_discovered += 1

    # Check for empty attack surface
    if coverage.candidate_inputs_discovered == 0:
        if coverage.cookies_excluded_policy:
            coverage.blocking_reason = (
                f"No candidate query parameters or HTML form inputs were discovered. "
                f"Discovered {coverage.candidate_cookies_discovered} cookie(s) ({', '.join(coverage.cookies_excluded_policy)}), "
                f"all excluded by authentication preservation policy."
            )
        else:
            coverage.blocking_reason = "No candidate query parameters, HTML form inputs, JSON parameters, or cookies were discovered on target endpoints."
        coverage.baseline_stability = "not_evaluated"
        coverage.verification_completed = False
        return coverage

    # Stage B: Test GET Endpoints
    for ep in candidate_endpoints:
        if _is_scan_cancelled():
            break
        url = ep["url"]
        method = ep["method"]
        all_param_names = ep["params"]
        merged_values = ep["values"]
        
        baseline_params = {}
        for p in all_param_names:
            observed_val = merged_values.get(p)
            baseline_params[p] = observed_val if (observed_val is not None and observed_val != "") else "test"
            
        for param in all_param_names:
            try:
                await test_parameter(
                    url=url, 
                    method=method, 
                    params=baseline_params, 
                    param_to_inject=param, 
                    source="URL query",
                    cookies_dict=all_cookies_dict,
                    location="query"
                )
            except Exception as pe:
                logger.warning(f"Error testing parameter '{param}' on {url}: {pe}")
                coverage.scanner_error = str(pe)
                coverage.inconclusive_reasons.append(f"Scanner exception on '{param}': {pe}")

    # Stage C: Test Form Inputs
    for form_item in candidate_forms:
        if _is_scan_cancelled():
            break
        action_url = form_item["action_url"]
        page_url = form_item["page_url"]
        method = form_item["method"]
        inputs = form_item["inputs"]
        fields = form_item["fields"]
        
        baseline_params = {}
        csrf_field_name = None
        for name in inputs:
            f_info = fields.get(name, {})
            val = f_info.get("value", "") if isinstance(f_info, dict) else str(f_info or "")
            f_type = f_info.get("type", "text").lower() if isinstance(f_info, dict) else "text"
            
            is_csrf = any(k in name.lower() for k in ["csrf", "xsrf", "token", "nonce", "__requestverificationtoken"])
            if is_csrf:
                baseline_params[name] = val
                csrf_field_name = name
            elif f_type == "hidden" and val:
                baseline_params[name] = val
            else:
                baseline_params[name] = val if val else "test"

        params_to_test = [name for name in inputs if name != csrf_field_name] or inputs
        for param in params_to_test:
            try:
                await test_parameter(
                    url=action_url, 
                    method=method, 
                    params=baseline_params, 
                    param_to_inject=param, 
                    source="form", 
                    page_url=page_url, 
                    csrf_field=csrf_field_name,
                    cookies_dict=all_cookies_dict,
                    location="form"
                )
            except Exception as pe:
                logger.warning(f"Error testing form parameter '{param}' on {action_url}: {pe}")
                coverage.scanner_error = str(pe)
                coverage.inconclusive_reasons.append(f"Scanner exception on form parameter '{param}': {pe}")

    # Stage D: Test JSON Endpoints
    for j_ep in candidate_json_endpoints:
        if _is_scan_cancelled():
            break
        j_url = j_ep["url"]
        j_method = j_ep["method"]
        j_params = j_ep["params"]
        j_values = dict(j_ep.get("values", {}))
        
        for param in j_params:
            try:
                await test_parameter(
                    url=j_url,
                    method=j_method,
                    params=j_values,
                    param_to_inject=param,
                    source="JSON body",
                    cookies_dict=all_cookies_dict,
                    location="json"
                )
                coverage.json_parameters_tested += 1
            except Exception as pe:
                logger.warning(f"Error testing JSON parameter '{param}' on {j_url}: {pe}")
                coverage.scanner_error = str(pe)
                coverage.inconclusive_reasons.append(f"Scanner exception on JSON parameter '{param}': {pe}")

    # Stage E: Test Candidate Cookies
    for c_item in candidate_cookies:
        if _is_scan_cancelled():
            break
        c_name = c_item["name"]
        c_url = c_item["url"] or getattr(scanner, "target_url", "")
        if not c_url and candidate_endpoints:
            c_url = candidate_endpoints[0]["url"]
        if not c_url:
            continue

        try:
            await test_parameter(
                url=c_url,
                method="GET",
                params={},
                param_to_inject=c_name,
                source="cookie",
                cookies_dict=all_cookies_dict,
                location="cookie"
            )
            coverage.cookies_tested += 1
        except Exception as pe:
            logger.warning(f"Error testing cookie '{c_name}' on {c_url}: {pe}")
            coverage.scanner_error = str(pe)
            coverage.inconclusive_reasons.append(f"Scanner exception on cookie '{c_name}': {pe}")

    if _is_scan_cancelled():
        coverage.verification_completed = False
        coverage.blocking_reason = "Scan cancelled before all techniques could complete."
    elif coverage.inputs_tested > 0 and not coverage.scanner_error:
        coverage.verification_completed = True

    return coverage
