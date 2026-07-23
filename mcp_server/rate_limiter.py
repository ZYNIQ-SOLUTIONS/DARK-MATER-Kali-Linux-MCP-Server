"""
Rate limiting module for MCP Kali Server.
Prevents abuse and ensures service stability.
"""

import time
import asyncio
import logging
from typing import Dict, Optional, Tuple
from collections import defaultdict, deque
from datetime import datetime, timedelta
from fastapi import HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class RateLimitConfig(BaseModel):
    """Rate limit configuration."""
    requests_per_minute: int = 20
    requests_per_hour: int = 500
    burst_limit: int = 10
    tool_requests_per_minute: int = 20
    enabled: bool = True

class RateLimiter:
    """Thread-safe rate limiter with sliding window."""
    
    def __init__(self, config: RateLimitConfig = None):
        self.config = config or RateLimitConfig()
        self._request_history: Dict[str, deque] = defaultdict(deque)
        self._tool_history: Dict[str, deque] = defaultdict(deque)
        self._lock = asyncio.Lock()
        
    async def check_rate_limit(self, client_id: str, endpoint: str = "general") -> bool:
        """
        Check if request is within rate limits.
        
        Args:
            client_id: Client identifier (IP or API key)
            endpoint: Endpoint being accessed
            
        Returns:
            True if within limits, False otherwise
        """
        if not self.config.enabled:
            return True
            
        async with self._lock:
            now = time.time()
            
            # Clean old entries
            self._clean_old_entries(client_id, now)
            
            # Check different limits based on endpoint
            if endpoint.startswith("/tools/"):
                return await self._check_tool_limits(client_id, now)
            else:
                return await self._check_general_limits(client_id, now)
    
    async def _check_general_limits(self, client_id: str, now: float) -> bool:
        """Check general API rate limits."""
        history = self._request_history[client_id]
        
        # Check burst limit (last 60 seconds)
        recent_requests = sum(1 for req_time in history if now - req_time <= 60)
        if recent_requests >= self.config.burst_limit:
            logger.warning(f"Burst limit exceeded for client {client_id}: {recent_requests}")
            return False
            
        # Check per-minute limit
        minute_requests = sum(1 for req_time in history if now - req_time <= 60)
        if minute_requests >= self.config.requests_per_minute:
            logger.warning(f"Per-minute limit exceeded for client {client_id}: {minute_requests}")
            return False
            
        # Check per-hour limit
        hour_requests = sum(1 for req_time in history if now - req_time <= 3600)
        if hour_requests >= self.config.requests_per_hour:
            logger.warning(f"Per-hour limit exceeded for client {client_id}: {hour_requests}")
            return False
            
        # Record this request
        history.append(now)
        return True
        
    async def _check_tool_limits(self, client_id: str, now: float) -> bool:
        """Check tool-specific rate limits (more restrictive)."""
        history = self._tool_history[client_id]
        
        # Check tool-specific per-minute limit
        minute_requests = sum(1 for req_time in history if now - req_time <= 60)
        if minute_requests >= self.config.tool_requests_per_minute:
            logger.warning(f"Tool rate limit exceeded for client {client_id}: {minute_requests}")
            return False
            
        # Record this request
        history.append(now)
        return True
        
    def _clean_old_entries(self, client_id: str, now: float):
        """Remove entries older than 1 hour."""
        cutoff = now - 3600  # 1 hour ago
        
        # Clean general history
        history = self._request_history[client_id]
        while history and history[0] < cutoff:
            history.popleft()
            
        # Clean tool history
        tool_history = self._tool_history[client_id]
        while tool_history and tool_history[0] < cutoff:
            tool_history.popleft()
    
    async def get_client_stats(self, client_id: str) -> Dict[str, int]:
        """Get current rate limit stats for a client."""
        async with self._lock:
            now = time.time()
            self._clean_old_entries(client_id, now)
            
            general_history = self._request_history[client_id]
            tool_history = self._tool_history[client_id]
            
            return {
                "requests_last_minute": sum(1 for t in general_history if now - t <= 60),
                "requests_last_hour": sum(1 for t in general_history if now - t <= 3600),
                "tool_requests_last_minute": sum(1 for t in tool_history if now - t <= 60),
                "remaining_requests_per_minute": max(0, self.config.requests_per_minute - sum(1 for t in general_history if now - t <= 60)),
                "remaining_tool_requests_per_minute": max(0, self.config.tool_requests_per_minute - sum(1 for t in tool_history if now - t <= 60))
            }

# Global rate limiter instance
rate_limiter = RateLimiter()

async def rate_limit_middleware(request: Request, client_id: str) -> None:
    """
    FastAPI middleware for rate limiting.
    
    Args:
        request: FastAPI request object
        client_id: Client identifier
        
    Raises:
        HTTPException: If rate limit exceeded
    """
    endpoint = request.url.path
    
    if not await rate_limiter.check_rate_limit(client_id, endpoint):
        stats = await rate_limiter.get_client_stats(client_id)
        
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Rate limit exceeded",
                "message": "Too many requests. Please wait before trying again.",
                "stats": stats,
                "retry_after": 60  # seconds
            },
            headers={"Retry-After": "60"}
        )

def get_client_identifier(request: Request) -> str:
    """Extract client identifier from request."""
    # Try to get API key from authorization header
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        api_key = auth_header[7:]
        # Use last 8 characters of API key for identification
        return f"key_{api_key[-8:]}" if len(api_key) >= 8 else f"key_{api_key}"
    
    # Fall back to IP address
    client_ip = request.client.host if request.client else "unknown"
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    
    return f"ip_{client_ip}"

async def apply_rate_limiting(request: Request) -> None:
    """Apply rate limiting to request."""
    client_id = get_client_identifier(request)
    await rate_limit_middleware(request, client_id)