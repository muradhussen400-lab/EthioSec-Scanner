import asyncio
import logging
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode, urlunparse
from typing import Dict, Any, List, Set, Tuple, Optional
from .http_client import SafeHTTPClient

logger = logging.getLogger("ethiosec.scanner.crawler")


class Crawler:
    """
    High-fidelity, scope-enforcing Web Crawler and Attack Surface Discovery Engine.
    Discovers same-origin endpoints, query parameters, HTML forms, content types,
    status codes, cookies, and JavaScript-embedded API routes.
    """
    def __init__(self, start_url: str, client: SafeHTTPClient, max_pages: int = 20, max_depth: int = 2):
        self.start_url = start_url
        self.client = client
        self.max_pages = max_pages
        self.max_depth = max_depth
        
        parsed_start = urlparse(start_url)
        self.base_domain = parsed_start.hostname
        self.base_scheme = parsed_start.scheme
        self.base_port = parsed_start.port
        
        norm_start = self._normalize_url_for_crawling(start_url)
        self.visited_urls: Set[str] = set()
        self.enqueued_urls: Set[str] = {norm_start}
        self.to_visit: List[Tuple[str, int]] = [(norm_start, 0)]  # (url, depth)
        
        # Endpoint inventory tracking: (method, path) -> endpoint metadata
        self.endpoints: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.discovered_forms: List[Dict[str, Any]] = []
        
        # Telemetry & Inventory metadata
        self.content_types_observed: Dict[str, int] = {}
        self.status_codes_observed: Dict[int, int] = {}
        self.cookies_observed: List[Dict[str, Any]] = []
        self._seen_cookie_names: Set[str] = set()
        self.api_routes: Set[str] = set()
        self.redirect_chains: List[Dict[str, str]] = []
        
        # Regex to detect REST/JSON API routes inside scripts or inline JavaScript
        self._api_route_pattern = re.compile(
            r'["\'](/(?:api|v[0-9]+|auth|users?|account|admin|search|data|items?|items?/[0-9]+)[a-zA-Z0-9_\-/\.?=&]*)["\']',
            re.IGNORECASE
        )

    def _is_same_origin(self, url: str) -> bool:
        """Enforces strictly authorized same-origin scope boundaries."""
        try:
            parsed = urlparse(url)
            if not parsed.hostname:
                return False
            # Check domain
            if parsed.hostname.lower() != (self.base_domain or "").lower():
                return False
            # Check scheme (allow http <-> https transitions on same host)
            if parsed.scheme not in ("http", "https"):
                return False
            # Check port match if explicitly declared
            if self.base_port and parsed.port and parsed.port != self.base_port:
                return False
            return True
        except Exception:
            return False

    def _normalize_url_for_crawling(self, url: str) -> str:
        """Normalizes URLs for deduplication during crawl, stripping fragments."""
        try:
            parsed = urlparse(url)
            return parsed._replace(fragment="").geturl()
        except Exception:
            return url

    def _record_cookies(self, response: Any):
        """Extracts and inventories Set-Cookie directives observed during crawling."""
        if not response or not hasattr(response, "headers"):
            return
        try:
            raw_cookies = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
            if not raw_cookies:
                for k, v in getattr(response.headers, "items", lambda: [])():
                    if str(k).lower() == "set-cookie":
                        raw_cookies.append(v)
                
            for c_str in raw_cookies:
                parts = [p.strip() for p in c_str.split(";")]
                if not parts:
                    continue
                name_val = parts[0].split("=", 1)
                c_name = name_val[0].strip()
                if not c_name or c_name in self._seen_cookie_names:
                    continue
                self._seen_cookie_names.add(c_name)
                
                flags = [p.lower() for p in parts[1:]]
                self.cookies_observed.append({
                    "name": c_name,
                    "secure": any("secure" in f for f in flags),
                    "httponly": any("httponly" in f for f in flags),
                    "samesite": next((f.split("=")[1].strip() for f in flags if f.startswith("samesite")), None),
                    "is_session": any(k in c_name.lower() for k in ("session", "token", "auth", "jwt", "sid"))
                })
        except Exception as e:
            logger.debug(f"Cookie recording notice: {e}")

    def _extract_script_api_routes(self, text: str, page_url: str):
        """Scans response text / scripts for JavaScript-declared API routes."""
        if not text:
            return
        try:
            matches = self._api_route_pattern.findall(text)
            for route in matches:
                # Filter out obvious false positives like file extensions or single slashes
                if route in ("/", "//") or route.endswith((".png", ".jpg", ".css", ".svg", ".woff", ".ico")):
                    continue
                full_api_url = urljoin(page_url, route)
                if self._is_same_origin(full_api_url):
                    self.api_routes.add(full_api_url)
                    norm_api = self._normalize_url_for_crawling(full_api_url)
                    self._register_endpoint(norm_api, "GET", "javascript_route")
        except Exception as e:
            logger.debug(f"Script route extraction notice: {e}")

    def _register_endpoint(
        self, 
        url: str, 
        method: str, 
        source: str, 
        params: Optional[List[str]] = None, 
        param_values: Optional[Dict[str, str]] = None,
        content_type: Optional[str] = None,
        status_code: Optional[int] = None,
        requires_auth: bool = False
    ):
        """Registers and merges unique attack surface endpoints preserving parameters and repeated keys."""
        try:
            parsed = urlparse(url)
            method = method.upper().strip()
            endpoint_key = (method, parsed.path)
            
            # Parse query parameters with support for duplicate keys
            query_tuples = parse_qsl(parsed.query, keep_blank_values=True)
            q_dict: Dict[str, str] = {}
            repeated_keys: Dict[str, List[str]] = {}
            for k, v in query_tuples:
                if k not in q_dict:
                    q_dict[k] = v
                else:
                    if k not in repeated_keys:
                        repeated_keys[k] = [q_dict[k]]
                    repeated_keys[k].append(v)
            
            param_names = [k for k, _ in query_tuples] if method == "GET" else list(params or [])
            combined_values = dict(q_dict)
            if param_values:
                combined_values.update(param_values)
                
            base_endpoint_url = urlunparse(parsed._replace(query="")) if method == "GET" else url
            
            if endpoint_key not in self.endpoints:
                self.endpoints[endpoint_key] = {
                    "url": base_endpoint_url,
                    "method": method,
                    "params": set(param_names),
                    "param_values": combined_values,
                    "repeated_params": repeated_keys,
                    "content_type": content_type or "text/html",
                    "status_code": status_code,
                    "source": source,
                    "requires_auth": requires_auth
                }
            else:
                ep = self.endpoints[endpoint_key]
                ep["params"].update(param_names)
                for k, v in combined_values.items():
                    if k not in ep["param_values"] or not ep["param_values"][k]:
                        ep["param_values"][k] = v
                if repeated_keys:
                    if "repeated_params" not in ep:
                        ep["repeated_params"] = {}
                    ep["repeated_params"].update(repeated_keys)
                if content_type and not ep.get("content_type"):
                    ep["content_type"] = content_type
                if status_code and not ep.get("status_code"):
                    ep["status_code"] = status_code
                if requires_auth:
                    ep["requires_auth"] = True
        except Exception as e:
            logger.debug(f"Error registering endpoint {url}: {e}")

    async def run(self) -> Dict[str, Any]:
        """
        Executes bounded BFS crawl over authorized same-origin targets.
        Returns crawled URLs, endpoints, discovered forms, and comprehensive inventory.
        """
        while self.to_visit and len(self.visited_urls) < self.max_pages:
            current_url, depth = self.to_visit.pop(0)
            
            normalized = self._normalize_url_for_crawling(current_url)
            if normalized in self.visited_urls:
                continue
                
            self.visited_urls.add(normalized)
            
            # Skip recursion beyond requested depth
            if depth >= self.max_depth:
                self._register_endpoint(normalized, "GET", "crawler")
                continue
                
            try:
                response = await self.client.get(normalized)
                if not response:
                    continue
                    
                # Track status code telemetry
                status_code = getattr(response, "status_code", 0)
                self.status_codes_observed[status_code] = self.status_codes_observed.get(status_code, 0) + 1
                
                # Check for redirect chain
                if status_code in (301, 302, 307, 308) and "location" in response.headers:
                    dest_url = urljoin(normalized, response.headers["location"])
                    self.redirect_chains.append({"source": normalized, "destination": dest_url, "status": status_code})
                    if self._is_same_origin(dest_url) and dest_url not in self.visited_urls and dest_url not in self.enqueued_urls:
                        self.enqueued_urls.add(dest_url)
                        self.to_visit.append((dest_url, depth + 1))
                    continue
                    
                # Record cookies
                self._record_cookies(response)
                
                # Check authentication requirements
                requires_auth = status_code in (401, 403)
                
                # Content-Type classification
                content_type = response.headers.get("Content-Type", "").lower()
                clean_ct = content_type.split(";")[0].strip() if content_type else "unknown"
                self.content_types_observed[clean_ct] = self.content_types_observed.get(clean_ct, 0) + 1
                
                self._register_endpoint(
                    normalized, "GET", "crawler", 
                    content_type=clean_ct, status_code=status_code, requires_auth=requires_auth
                )
                
                if not (200 <= status_code < 300):
                    continue
                    
                resp_text = getattr(response, "text", "")
                
                # Extract embedded API routes from text/scripts
                self._extract_script_api_routes(resp_text, normalized)
                
                if not any(ct in clean_ct for ct in ("text/html", "application/xhtml+xml", "text/xml")):
                    continue
                    
                soup = BeautifulSoup(resp_text, "html.parser")
                
                # 1. Extract Links from anchors and link tags
                for a_tag in soup.find_all(["a", "link"], href=True):
                    href = a_tag["href"].strip()
                    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                        continue
                        
                    full_url = urljoin(normalized, href)
                    full_norm = self._normalize_url_for_crawling(full_url)
                    
                    if self._is_same_origin(full_norm):
                        if full_norm not in self.visited_urls and full_norm not in self.enqueued_urls:
                            self.enqueued_urls.add(full_norm)
                            self.to_visit.append((full_norm, depth + 1))
                            
                # 2. Extract Forms with complete field metadata & CSRF token markers
                for form in soup.find_all("form"):
                    action = form.get("action", "") or ""
                    method = (form.get("method", "get") or "GET").upper()
                    full_action = urljoin(normalized, action)
                    full_action_norm = self._normalize_url_for_crawling(full_action)
                    
                    if not self._is_same_origin(full_action_norm):
                        continue
                        
                    inputs = []
                    fields = {}
                    csrf_tokens_found = []
                    
                    for input_tag in form.find_all(["input", "textarea", "select"]):
                        name = input_tag.get("name")
                        if not name:
                            continue
                        name = name.strip()
                        inputs.append(name)
                        
                        f_type = (input_tag.get("type", "text") or "text").lower()
                        f_val = input_tag.get("value", "") or ""
                        fields[name] = {
                            "value": f_val,
                            "type": f_type
                        }
                        
                        # Anti-CSRF marker detection
                        if any(marker in name.lower() for marker in ("csrf", "xsrf", "token", "nonce", "__requestverificationtoken")):
                            csrf_tokens_found.append(name)
                            
                    if inputs:
                        self.discovered_forms.append({
                            "page_url": normalized,
                            "action_url": full_action_norm,
                            "method": method,
                            "inputs": inputs,
                            "fields": fields,
                            "has_csrf_token": len(csrf_tokens_found) > 0,
                            "csrf_field_name": csrf_tokens_found[0] if csrf_tokens_found else None
                        })
                        form_param_vals = {k: v.get("value", "") for k, v in fields.items() if isinstance(v, dict)}
                        self._register_endpoint(
                            full_action_norm, method, "form", 
                            params=inputs, param_values=form_param_vals,
                            content_type="application/x-www-form-urlencoded" if method == "POST" else clean_ct,
                            status_code=status_code
                        )
                            
            except Exception as e:
                logger.warning(f"Crawler error on {normalized}: {e.__class__.__name__} - {str(e)}")
                
        # Format endpoints list for consumers
        formatted_endpoints = []
        total_inputs = 0
        for key, data in self.endpoints.items():
            param_list = sorted(list(data["params"]))
            data["params"] = param_list
            total_inputs += len(param_list)
            formatted_endpoints.append(data)
            
        inventory = {
            "total_endpoints": len(formatted_endpoints),
            "total_inputs": total_inputs,
            "content_types": self.content_types_observed,
            "status_codes": self.status_codes_observed,
            "cookies": self.cookies_observed,
            "api_routes": sorted(list(self.api_routes)),
            "redirect_chains": self.redirect_chains
        }
            
        return {
            "urls": list(self.visited_urls),
            "endpoints": formatted_endpoints,
            "forms": self.discovered_forms,
            "cookies": self.cookies_observed,
            "inventory": inventory
        }
