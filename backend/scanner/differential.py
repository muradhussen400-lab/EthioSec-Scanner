import httpx
import re
import difflib
import math
from typing import Dict, Any, List, Optional, Set

class BaselineEngine:
    """
    Compares two HTTP responses (baseline vs test) using multi-metric analysis
    (status codes, normalized content similarity, structural markers, and headers).
    """

    @staticmethod
    def _normalize_body(body: str) -> str:
        """
        Conservative normalization of dynamic tokens without destroying HTML/JSON structure.
        """
        if not body:
            return ""
        
        # 1. Strip dynamic anti-CSRF tokens and viewstates
        body = re.sub(r'(?i)(csrf[_-]?token|_csrf|authenticity_token|__requestverificationtoken)[\s:=]+["\']?[\w\d\-_]{8,}["\']?', r'\1=[TOKEN]', body)
        
        # 2. Strip session IDs, hex hashes (32+ chars), and UUIDs
        body = re.sub(r'\b[a-f0-9]{32,64}\b', '[HASH]', body, flags=re.IGNORECASE)
        body = re.sub(r'\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b', '[UUID]', body, flags=re.IGNORECASE)
        
        # 3. Strip ISO-8601 timestamps and Unix epoch timestamps
        body = re.sub(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b', '[DATETIME]', body)
        body = re.sub(r'\b\d{10,13}\b', '[TIMESTAMP]', body)
        
        # 4. Strip dynamic request/trace/span IDs
        body = re.sub(r'(?i)(request|req|trace|span|correlation|x-request)[_-]?id[\s:=]+["\']?[\w\d\-_]+["\']?', r'\1_id=[ID]', body)
        
        # 5. Normalize dynamic execution times (e.g. "generated in 0.042s" or "query time: 12ms")
        body = re.sub(r'(?i)(?:time|rendered|generated|elapsed)[\s:=]+[\d\.]+\s*(?:ms|s|seconds)?', 'time=[ELAPSED]', body)

        # 6. Normalize whitespace sequences to single space for stable layout comparison
        body = re.sub(r'[ \t\r\n]+', ' ', body).strip()
        
        return body

    @staticmethod
    def _similarity_ratio(str1: str, str2: str, max_chars: int = 25000) -> float:
        """
        Computes text similarity ratio between two strings using standard SequenceMatcher.
        Caps length at max_chars for bounded execution time.
        """
        if str1 == str2:
            return 1.0
        if not str1 or not str2:
            return 0.0
        s1 = str1[:max_chars]
        s2 = str2[:max_chars]
        return difflib.SequenceMatcher(None, s1, s2).quick_ratio()

    @staticmethod
    def _is_similar(base_norm: str, test_norm: str, length_threshold: float = 0.12, ratio_threshold: float = 0.88) -> bool:
        """
        Multi-signal equivalence check: requires both text sequence similarity
        and bounded length difference ratio.
        """
        if base_norm == test_norm:
            return True
        
        len_base = len(base_norm)
        len_test = len(test_norm)
        
        if len_base == 0 or len_test == 0:
            return False
            
        diff_abs = abs(len_base - len_test)
        len_ratio = diff_abs / max(len_base, len_test)
        
        # If length differs by more than threshold, reject immediately
        if len_ratio > length_threshold and diff_abs > 40:
            return False
            
        # Compute SequenceMatcher similarity
        sim_ratio = BaselineEngine._similarity_ratio(base_norm, test_norm)
        return sim_ratio >= ratio_threshold

    @staticmethod
    def compare(baseline_resp: Optional[httpx.Response], test_resp: Optional[httpx.Response]) -> Dict[str, Any]:
        """
        Compares two HTTP responses and produces a comprehensive difference record.
        Handles missing or error responses safely.
        """
        if baseline_resp is None or test_resp is None:
            return {
                "status_match": False,
                "baseline_status": baseline_resp.status_code if baseline_resp else None,
                "test_status": test_resp.status_code if test_resp else None,
                "body_length_diff": 0,
                "length_ratio": 1.0,
                "similarity_ratio": 0.0,
                "is_body_identical": False,
                "is_body_similar": False,
                "content_type_changed": False,
                "baseline_redirect": False,
                "test_redirect": False,
                "redirect_changed": False,
                "incomparable": True
            }

        norm_base = BaselineEngine._normalize_body(baseline_resp.text)
        norm_test = BaselineEngine._normalize_body(test_resp.text)
        
        len_base = len(norm_base)
        len_test = len(norm_test)
        diff_abs = abs(len_test - len_base)
        max_len = max(len_base, len_test)
        length_ratio = (diff_abs / max_len) if max_len > 0 else 0.0
        
        sim_ratio = 1.0 if norm_base == norm_test else BaselineEngine._similarity_ratio(norm_base, norm_test)
        is_identical = (norm_base == norm_test)
        
        status_match = (baseline_resp.status_code == test_resp.status_code)
        
        # Multi-signal body similarity
        if is_identical:
            is_similar = True
        elif not status_match:
            # Different status codes mean distinct responses unless both are successful redirects
            is_similar = False
        else:
            is_similar = (sim_ratio >= 0.88 and length_ratio <= 0.12) or (diff_abs < 25 and sim_ratio >= 0.80)

        base_ct = baseline_resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
        test_ct = test_resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
        ct_changed = bool(base_ct and test_ct and base_ct != test_ct)
        
        base_redir = baseline_resp.status_code in (301, 302, 303, 307, 308)
        test_redir = test_resp.status_code in (301, 302, 303, 307, 308)
        
        return {
            "status_match": status_match,
            "baseline_status": baseline_resp.status_code,
            "test_status": test_resp.status_code,
            "body_length_diff": len(test_resp.text) - len(baseline_resp.text),
            "length_ratio": round(length_ratio, 4),
            "similarity_ratio": round(sim_ratio, 4),
            "is_body_identical": is_identical,
            "is_body_similar": is_similar,
            "content_type_changed": ct_changed,
            "baseline_redirect": base_redir,
            "test_redirect": test_redir,
            "redirect_changed": (base_redir != test_redir),
            "incomparable": False
        }

class BaselineProfile:
    """
    Represents the expected behavior and stability profile of an endpoint
    established from multiple baseline requests.
    """
    def __init__(self, requests: List[httpx.Response], db_error_checker=None):
        self.requests = [r for r in requests if r is not None]
        self.is_empty = len(self.requests) == 0
        self.is_stable = True
        self.baseline_status: Optional[int] = None
        self.baseline_has_db_errors = False
        self.mean_response_time = 0.0
        self.std_response_time = 0.0
        self.common_tokens: Set[str] = set()
        self.stability_ratio = 1.0
        self.stability_reason = "Stable baseline established"

        if self.is_empty:
            self.is_stable = False
            self.stability_reason = "Empty baseline (no valid HTTP responses received)"
            return
            
        self.baseline_status = self.requests[0].status_code
        
        # Check for non-standard baseline statuses (e.g. WAF block or server error)
        if self.baseline_status in (403, 429, 502, 503, 504):
            self.is_stable = False
            self.stability_reason = f"Baseline returned blocked or failure status: HTTP {self.baseline_status}"
            
        self.normalized_bodies = [BaselineEngine._normalize_body(r.text) for r in self.requests]
        
        # Measure response times
        times = []
        for r in self.requests:
            if hasattr(r, "duration"):
                try:
                    times.append(float(r.duration))
                    continue
                except Exception:
                    pass
            try:
                if hasattr(r, "_elapsed") and r._elapsed is not None:
                    times.append(r._elapsed.total_seconds())
                    continue
                el = getattr(r, "elapsed", None)
                if el is not None:
                    times.append(el.total_seconds())
            except (RuntimeError, Exception):
                pass
        if times:
            self.mean_response_time = sum(times) / len(times)
            if len(times) > 1:
                variance = sum((t - self.mean_response_time) ** 2 for t in times) / (len(times) - 1)
                self.std_response_time = math.sqrt(variance)
                
        # Evaluate stability across baseline requests
        if len(self.normalized_bodies) > 1:
            first_body = self.normalized_bodies[0]
            first_status = self.requests[0].status_code
            for idx, (b, r) in enumerate(zip(self.normalized_bodies[1:], self.requests[1:]), start=1):
                if r.status_code != first_status:
                    self.is_stable = False
                    self.stability_reason = f"Baseline status code varied between requests ({first_status} vs {r.status_code})"
                    break
                if not BaselineEngine._is_similar(first_body, b):
                    self.is_stable = False
                    self.stability_reason = "Baseline response body varied significantly between identical requests"
                    break

        lengths = [len(b) for b in self.normalized_bodies]
        self.min_length = min(lengths)
        self.max_length = max(lengths)
        
        # Extract common word tokens for structural marker checks
        token_sets = [set(re.findall(r'\b[a-zA-Z]{3,}\b', b.lower())) for b in self.normalized_bodies]
        if token_sets:
            self.common_tokens = set.intersection(*token_sets)

        # Populate baseline_has_db_errors and baseline_db_errors using db_error_checker if provided
        self.baseline_db_errors: Set[str] = set()
        if db_error_checker:
            for r in self.requests:
                db_name, err = db_error_checker(r.text)
                if db_name:
                    self.baseline_has_db_errors = True
                    self.baseline_db_errors.add(err)

    def compare_test(self, test_resp: Optional[httpx.Response]) -> Dict[str, Any]:
        """
        Compares test response against the baseline.
        """
        if self.is_empty or not self.requests:
            return {
                "status_match": False,
                "is_body_identical": False,
                "is_body_similar": False,
                "similarity_ratio": 0.0,
                "incomparable": True
            }
        return BaselineEngine.compare(self.requests[0], test_resp)

