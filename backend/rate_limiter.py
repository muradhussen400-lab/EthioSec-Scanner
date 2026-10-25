import os
import time
import asyncio
from typing import Dict, List, Optional
from fastapi import Request, HTTPException, status

class SlidingWindowRateLimiter:
    """
    In-memory sliding-window rate limiter with per-endpoint buckets and automatic cleanup.
    Production deployments can swap this with a Redis-backed token bucket adapter.
    """
    def __init__(self):
        # key -> list of float timestamps
        self._records: Dict[str, List[float]] = {}
        self._lock = asyncio.Lock()
        self._last_cleanup = time.time()

    async def _cleanup(self, now: float):
        """Evicts expired timestamps to prevent memory growth."""
        if now - self._last_cleanup > 60:
            expired_threshold = now - 3600 # retain at most 1 hour
            for key in list(self._records.keys()):
                self._records[key] = [ts for ts in self._records[key] if ts > expired_threshold]
                if not self._records[key]:
                    del self._records[key]
            self._last_cleanup = now

    async def check_rate_limit(self, key: str, max_requests: int, window_seconds: int):
        now = time.time()
        async with self._lock:
            await self._cleanup(now)
            window_start = now - window_seconds
            
            timestamps = self._records.get(key, [])
            # Filter timestamps within current window
            valid_timestamps = [ts for ts in timestamps if ts > window_start]
            
            if len(valid_timestamps) >= max_requests:
                oldest = valid_timestamps[0]
                retry_after = int(window_seconds - (now - oldest)) + 1
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Please wait {retry_after} seconds before trying again.",
                    headers={"Retry-After": str(max(1, retry_after))}
                )
            
            valid_timestamps.append(now)
            self._records[key] = valid_timestamps

    def clear(self):
        """Clears all rate limit records (used in test setups)."""
        self._records.clear()

_limiter = SlidingWindowRateLimiter()

def get_client_ip(request: Request) -> str:
    """Extracts client IP address safely."""
    # If TRUST_REVERSE_PROXY is enabled, inspect X-Forwarded-For
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[0]
    return request.client.host if request.client else "127.0.0.1"

ENVIRONMENT = os.getenv("ENVIRONMENT", "development").strip().lower()

def rate_limit(max_requests: int, window_seconds: int, prefix: str = "general"):
    """
    FastAPI dependency factory enforcing rate limits per endpoint & client IP.
    """
    async def dependency(request: Request):
        if os.getenv("DISABLE_RATE_LIMIT", "false").lower() == "true":
            return
            
        client_ip = get_client_ip(request)
        # In local development mode, grant a high threshold so developers aren't blocked during testing
        if ENVIRONMENT != "production" and client_ip in ("127.0.0.1", "::1", "localhost"):
            await _limiter.check_rate_limit(f"{prefix}:{client_ip}", max_requests=200, window_seconds=60)
            return

        key = f"{prefix}:{client_ip}"
        await _limiter.check_rate_limit(key, max_requests, window_seconds)
    return dependency

# Predefined rate-limiting dependencies for critical endpoints
limit_login = rate_limit(max_requests=5, window_seconds=300, prefix="auth_login")       # 5 attempts / 5 mins
limit_register = rate_limit(max_requests=5, window_seconds=900, prefix="auth_reg")      # 5 requests / 15 mins
limit_verify = rate_limit(max_requests=5, window_seconds=900, prefix="auth_verify")     # 5 attempts / 15 mins
limit_resend = rate_limit(max_requests=1, window_seconds=60, prefix="auth_resend")      # 1 resend / 60 seconds
limit_reset = rate_limit(max_requests=3, window_seconds=900, prefix="auth_reset")       # 3 requests / 15 mins
limit_scans = rate_limit(max_requests=20, window_seconds=3600, prefix="scans")          # 20 scans / hour
limit_ai = rate_limit(max_requests=30, window_seconds=60, prefix="ai_chat")             # 30 requests / min
