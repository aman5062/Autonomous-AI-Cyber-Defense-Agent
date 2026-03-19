import logging
from collections import defaultdict
import time

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    In-memory rate limiter (complements NGINX rate limiting).
    Tracks per-IP request counts and flags excessive traffic.
    """

    def __init__(self, max_requests: int = 60, window: int = 60):
        self.max_requests = max_requests
        self.window = window
        self._counts: dict = defaultdict(list)
        self._rate_limited: set = set()

    def check(self, ip: str) -> bool:
        """Returns True if IP should be rate-limited."""
        now = time.time()
        self._counts[ip] = [t for t in self._counts[ip] if now - t <= self.window]
        self._counts[ip].append(now)

        if len(self._counts[ip]) > self.max_requests:
            self._rate_limited.add(ip)
            logger.warning(f"Rate limit exceeded for {ip}: {len(self._counts[ip])} req/{self.window}s")
            return True
        return False

    def is_rate_limited(self, ip: str) -> bool:
        return ip in self._rate_limited

    def clear(self, ip: str):
        self._rate_limited.discard(ip)
        self._counts.pop(ip, None)
