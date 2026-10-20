import asyncio
import logging
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode, urlunparse
from .http_client import SafeHTTPClient

logger = logging.getLogger("ethiosec.scanner.crawler")

class Crawler:
    def __init__(self, start_url: str, client: SafeHTTPClient, max_pages: int = 20, max_depth: int = 2):
        self.start_url = start_url
        self.client = client
        self.max_pages = max_pages
        self.max_depth = max_depth
        
        parsed_start = urlparse(start_url)
        self.base_domain = parsed_start.hostname
        self.base_scheme = parsed_start.scheme
        
        norm_start = self._normalize_url_for_crawling(start_url)
        self.visited_urls = set()
        self.enqueued_urls = {norm_start}
        self.to_visit = [(norm_start, 0)]  # (url, depth)
        
        # Endpoint tracking
        # We store unique endpoints as (method, path) to avoid testing the same endpoint multiple times
        self.endpoints = {} 
        self.discovered_forms = []
        
    def _is_same_origin(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.hostname == self.base_domain
        
    def _normalize_url_for_crawling(self, url: str) -> str:
        # For crawling, we visit unique paths+queries, but ignore fragments
        parsed = urlparse(url)
        return parsed._replace(fragment="").geturl()

    def _register_endpoint(self, url: str, method: str, source: str, params: list = None, param_values: dict = None):
        parsed = urlparse(url)
        
        # If it's a GET, parse query params
        if method == "GET":
            query_params = parse_qsl(parsed.query)
            q_dict = dict(query_params)
            # Add to endpoints
            endpoint_key = (method, parsed.path)
            if endpoint_key not in self.endpoints:
                self.endpoints[endpoint_key] = {
                    "url": urlunparse(parsed._replace(query="")),  # base URL without query
                    "method": method,
                    "params": set([k for k, v in query_params]),
                    "param_values": q_dict,
                    "source": source
                }
            else:
                self.endpoints[endpoint_key]["params"].update([k for k, v in query_params])
                if "param_values" not in self.endpoints[endpoint_key]:
                    self.endpoints[endpoint_key]["param_values"] = {}
                for k, v in query_params:
                    if k not in self.endpoints[endpoint_key]["param_values"] or not self.endpoints[endpoint_key]["param_values"][k]:
                        self.endpoints[endpoint_key]["param_values"][k] = v
        elif method == "POST":
            # For POST, we rely on the forms list for parameters usually, but we register the endpoint
            endpoint_key = (method, parsed.path)
            if endpoint_key not in self.endpoints:
                self.endpoints[endpoint_key] = {
                    "url": url,
                    "method": method,
                    "params": set(params or []),
                    "param_values": dict(param_values or {}),
                    "source": source
                }
            elif param_values:
                if "param_values" not in self.endpoints[endpoint_key]:
                    self.endpoints[endpoint_key]["param_values"] = {}
                self.endpoints[endpoint_key]["param_values"].update(param_values)

    async def run(self):
        while self.to_visit and len(self.visited_urls) < self.max_pages:
            current_url, depth = self.to_visit.pop(0)
            
            normalized = self._normalize_url_for_crawling(current_url)
            if normalized in self.visited_urls:
                continue
                
            self.visited_urls.add(normalized)
            self._register_endpoint(normalized, "GET", "crawler")
            
            if depth >= self.max_depth:
                continue
                
            try:
                response = await self.client.get(normalized)
                if not (200 <= response.status_code < 300):
                    continue
                    
                content_type = response.headers.get("Content-Type", "").lower()
                if content_type and not any(ct in content_type for ct in ("text/html", "application/xhtml+xml", "text/xml")):
                    continue
                    
                soup = BeautifulSoup(response.text, "html.parser")
                
                # Extract Links from anchors and buttons
                for a_tag in soup.find_all(["a", "link"], href=True):
                    href = a_tag["href"]
                    full_url = urljoin(normalized, href)
                    full_norm = self._normalize_url_for_crawling(full_url)
                    
                    parsed = urlparse(full_norm)
                    if parsed.scheme in ["http", "https"] and self._is_same_origin(full_norm):
                        if full_norm not in self.visited_urls and full_norm not in self.enqueued_urls:
                            self.enqueued_urls.add(full_norm)
                            self.to_visit.append((full_norm, depth + 1))
                            
                # Extract Forms
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "get").upper()
                    full_action = urljoin(normalized, action)
                    full_action_norm = self._normalize_url_for_crawling(full_action)
                    
                    # Ensure form action stays within same-origin boundaries
                    if not self._is_same_origin(full_action_norm):
                        continue
                        
                    inputs = []
                    fields = {}
                    for input_tag in form.find_all(["input", "textarea", "select"]):
                        name = input_tag.get("name")
                        if name:
                            inputs.append(name)
                            fields[name] = {
                                "value": input_tag.get("value", ""),
                                "type": input_tag.get("type", "text").lower()
                            }
                            
                    if inputs:
                        self.discovered_forms.append({
                            "page_url": normalized,
                            "action_url": full_action_norm,
                            "method": method,
                            "inputs": inputs,
                            "fields": fields
                        })
                        form_param_vals = {k: v.get("value", "") for k, v in fields.items() if isinstance(v, dict)}
                        self._register_endpoint(full_action_norm, method, "form", params=inputs, param_values=form_param_vals)
                            
            except Exception as e:
                logger.warning(f"Crawler error on {normalized}: {e.__class__.__name__} - {str(e)}")
                
        # Convert sets to lists for JSON serialization and easier handling
        formatted_endpoints = []
        for key, data in self.endpoints.items():
            data["params"] = list(data["params"])
            formatted_endpoints.append(data)
            
        return {
            "urls": list(self.visited_urls),  # Keep list of raw URLs for backward compatibility
            "endpoints": formatted_endpoints,
            "forms": self.discovered_forms
        }
