import httpx
import logging
import asyncio
import os
import time
from urllib.parse import urljoin
from .safety import is_safe_url, UnsafeTargetError

logger = logging.getLogger(__name__)

class SafeHTTPClient:
    def __init__(self, timeout=10.0, max_redirects=3, max_response_size=5 * 1024 * 1024, max_concurrency=10, rate_limit_delay=0.1):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_response_size = max_response_size
        self.rate_limit_delay = rate_limit_delay
        
        verify_ssl = os.getenv("VERIFY_SSL", "true").lower() == "true"
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=verify_ssl)
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.last_request_time = 0.0
        self.lock = asyncio.Lock()
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
        
    async def _rate_limit(self):
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_request_time
            if elapsed < self.rate_limit_delay:
                await asyncio.sleep(self.rate_limit_delay - elapsed)
            self.last_request_time = time.time()

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """
        Wrapper around httpx.AsyncClient.request that performs manual redirect
        following with SSRF checks on every hop, and limits response size.
        """
        redirects = 0
        current_url = url
        
        while redirects <= self.max_redirects:
            is_safe_url(current_url)
            
            async with self.semaphore:
                await self._rate_limit()
                try:
                    # We use stream to enforce max_response_size strictly without reading it all at once if it's too big
                    async with self.client.stream(method, current_url, **kwargs) as response:
                        content = b""
                        async for chunk in response.aiter_bytes():
                            content += chunk
                            if len(content) > self.max_response_size:
                                raise httpx.RequestError(f"Response size exceeded {self.max_response_size} bytes")
                        
                        # Reconstruct the response with read content
                        res = httpx.Response(
                            status_code=response.status_code,
                            headers=response.headers,
                            content=content,
                            request=response.request,
                            extensions=response.extensions
                        )
                        
                except httpx.RequestError as e:
                    logger.error(f"HTTP request error for {current_url}: {e}")
                    raise
                
            if res.status_code in (301, 302, 303, 307, 308):
                location = res.headers.get("Location")
                if not location:
                    return res
                    
                next_url = urljoin(current_url, location)
                current_url = next_url
                redirects += 1
                continue
                
            return res
            
        raise httpx.RequestError(f"Too many redirects (max {self.max_redirects})")

    async def get(self, url: str, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs):
        return await self.request("POST", url, **kwargs)
        
    async def head(self, url: str, **kwargs):
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs):
        return await self.request("OPTIONS", url, **kwargs)
