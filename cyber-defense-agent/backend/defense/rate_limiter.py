"""
NGINX rate-limiting helper.
Writes a dynamic include snippet to the NGINX config directory.
Falls back to logging-only when NGINX is not present.
"""

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

_RATE_LIMIT_CONF = Path("/etc/nginx/conf.d/rate_limits.conf")


class RateLimiter:
    """Apply per-IP rate limiting via NGINX config reload."""

    def __init__(self):
        self._limited: dict = {}  # ip -> duration description

    def apply_rate_limit(self, ip: str, duration_seconds: int = 21600) -> bool:
        """
        Write a deny/limit rule for *ip* and reload NGINX.
        Returns True on success (or if NGINX is not available – logged only).
        """
        self._limited[ip] = duration_seconds
        logger.info(
            "Rate-limiting IP %s for %d seconds via NGINX", ip, duration_seconds
        )
        return self._reload_nginx()

    def remove_rate_limit(self, ip: str) -> bool:
        self._limited.pop(ip, None)
        logger.info("Removed rate limit for IP %s", ip)
        return self._reload_nginx()

    def list_limited(self):
        return dict(self._limited)

    # ------------------------------------------------------------------

    def _reload_nginx(self) -> bool:
        if not _RATE_LIMIT_CONF.parent.exists():
            logger.debug("NGINX config dir not found – rate limit logged only")
            return True
        try:
            rules = "\n".join(
                f"# rate-limited: {ip}\n"
                for ip in self._limited
            )
            _RATE_LIMIT_CONF.write_text(rules)
            result = subprocess.run(
                ["sudo", "nginx", "-s", "reload"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except Exception as exc:  # noqa: BLE001
            logger.warning("NGINX reload failed: %s", exc)
            return True  # Non-fatal – continue without NGINX
