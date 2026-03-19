import time
import logging
from collections import defaultdict
from backend.config import settings

logger = logging.getLogger(__name__)

LOGIN_PATHS = {"/login", "/signin", "/auth", "/wp-login.php", "/admin", "/api/login", "/api/auth"}


class BruteForceDetector:
    def __init__(self):
        self.threshold = settings.BRUTE_FORCE_THRESHOLD
        self.window = settings.BRUTE_FORCE_WINDOW
        # ip -> list of timestamps of failed attempts
        self._attempts: dict = defaultdict(list)

    def detect(self, ip: str, path: str, status: int) -> dict:
        path_lower = path.split("?")[0].lower()
        is_login = any(path_lower.startswith(p) for p in LOGIN_PATHS)

        if not is_login:
            return {"detected": False}

        now = time.time()

        if status in (401, 403, 429):
            self._attempts[ip].append(now)

        # Prune old timestamps
        self._attempts[ip] = [t for t in self._attempts[ip] if now - t <= self.window]

        count = len(self._attempts[ip])
        if count >= self.threshold:
            return {
                "detected": True,
                "attack_type": "BRUTE_FORCE",
                "severity": "HIGH",
                "confidence": min(0.99, 0.7 + count * 0.05),
                "attempt_count": count,
                "time_window": self.window,
                "recommended_action": "BLOCK_IP",
                "details": f"{count} failed login attempts from {ip} in {self.window}s",
            }

        return {"detected": False}

    def reset_attempts(self, ip: str):
        self._attempts.pop(ip, None)
