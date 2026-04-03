"""
Cross-Site Scripting (XSS) detector.
"""

import re
import logging
import urllib.parse
from typing import Dict

from backend.detection.patterns import XSS_PATTERNS

logger = logging.getLogger(__name__)

_COMPILED = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in XSS_PATTERNS]

# Patterns that indicate a real script execution attempt (higher severity)
_EXEC_PATTERNS = [
    re.compile(r"<script[\s>]", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"document\.(cookie|write)", re.IGNORECASE),
]


class XSSDetector:
    """Detect Cross-Site Scripting (XSS) injection attempts."""

    def detect(self, path: str, body: str = "") -> Dict:
        target = _decode(path) + " " + _decode(body)

        # Check for execution-level patterns (CRITICAL)
        for p in _EXEC_PATTERNS:
            if p.search(target):
                return {
                    "detected": True,
                    "attack_type": "XSS",
                    "severity": "HIGH",
                    "pattern": p.pattern,
                    "confidence": 0.92,
                    "details": f"XSS execution pattern detected: {path[:200]}",
                    "recommended_action": "RATE_LIMIT",
                }

        # Generic XSS indicators
        for compiled in _COMPILED:
            if compiled.search(target):
                return {
                    "detected": True,
                    "attack_type": "XSS",
                    "severity": "MEDIUM",
                    "pattern": compiled.pattern,
                    "confidence": 0.75,
                    "details": f"XSS pattern detected: {path[:200]}",
                    "recommended_action": "RATE_LIMIT",
                }

        return {"detected": False, "attack_type": "XSS"}


def _decode(text: str) -> str:
    try:
        decoded = urllib.parse.unquote_plus(text)
        decoded = urllib.parse.unquote_plus(decoded)
        return decoded
    except Exception:
        return text
