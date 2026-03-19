import re
import logging
from urllib.parse import unquote_plus
from backend.detection.patterns import XSS_PATTERNS

logger = logging.getLogger(__name__)

_COMPILED = [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS]

_CRITICAL = re.compile(r"<script|javascript:|document\.cookie|document\.write", re.IGNORECASE)


class XSSDetector:
    def detect(self, path: str, method: str = "GET") -> dict:
        decoded = unquote_plus(path)

        matched = None
        for pattern in _COMPILED:
            if pattern.search(decoded):
                matched = pattern.pattern
                break

        if not matched:
            return {"detected": False}

        severity = "HIGH" if _CRITICAL.search(decoded) else "MEDIUM"

        return {
            "detected": True,
            "attack_type": "XSS",
            "severity": severity,
            "confidence": 0.88,
            "pattern": matched,
            "recommended_action": "BLOCK_IP" if severity == "HIGH" else "RATE_LIMIT",
            "details": f"XSS pattern detected in path: {path[:100]}",
        }
