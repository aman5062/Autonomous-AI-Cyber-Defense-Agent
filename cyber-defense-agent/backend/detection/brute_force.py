"""
Brute-force login detector using a sliding-window counter per IP.
"""

import logging
import time
from collections import defaultdict
from typing import Dict, List

from backend.config import settings

logger = logging.getLogger(__name__)

_LOGIN_PATHS = ("/login", "/signin", "/auth", "/wp-login", "/admin")
_FAIL_STATUSES = (401, 403)


class BruteForceDetector:
    """
    Track failed authentication attempts and raise an alert when
    an IP exceeds *threshold* failures within *time_window* seconds.
    """

    def __init__(
        self,
        threshold: int = None,
        time_window: int = None,
    ):
        self.threshold = threshold or settings.detection.brute_force_threshold
        self.time_window = time_window or settings.detection.brute_force_window
        # {ip: [epoch_timestamp, ...]}
        self._attempts: Dict[str, List[float]] = defaultdict(list)

    def detect(self, ip: str, path: str, status: int) -> Dict:
        """
        Record a request and return a detection result.

        Only counts as a failed login attempt when:
        - the path looks like an auth endpoint
        - the HTTP status indicates failure (401 / 403)
        """
        if not self._is_login_request(path, status):
            return {"detected": False, "attack_type": "BRUTE_FORCE"}

        now = time.time()
        attempts = self._attempts[ip]

        # Slide the window
        window_start = now - self.time_window
        self._attempts[ip] = [t for t in attempts if t >= window_start]
        self._attempts[ip].append(now)

        count = len(self._attempts[ip])

        if count >= self.threshold:
            logger.warning(
                "Brute force detected: IP=%s attempts=%d window=%ds",
                ip, count, self.time_window,
            )
            return {
                "detected": True,
                "attack_type": "BRUTE_FORCE",
                "severity": "HIGH",
                "confidence": min(0.6 + (count - self.threshold) * 0.05, 0.99),
                "attempt_count": count,
                "time_window": self.time_window,
                "details": (
                    f"{count} failed login attempts from {ip} "
                    f"in {self.time_window}s"
                ),
                "recommended_action": "BLOCK_IP",
            }

        return {"detected": False, "attack_type": "BRUTE_FORCE"}

    def reset_attempts(self, ip: str):
        """Clear attempt history for an IP (e.g. after successful login)."""
        self._attempts.pop(ip, None)

    def get_attempt_count(self, ip: str) -> int:
        now = time.time()
        window_start = now - self.time_window
        return sum(1 for t in self._attempts.get(ip, []) if t >= window_start)

    # ------------------------------------------------------------------
    def _is_login_request(self, path: str, status: int) -> bool:
        path_lower = path.lower().split("?")[0]
        is_login_path = any(path_lower.startswith(p) or path_lower == p
                            for p in _LOGIN_PATHS)
        return is_login_path and status in _FAIL_STATUSES
