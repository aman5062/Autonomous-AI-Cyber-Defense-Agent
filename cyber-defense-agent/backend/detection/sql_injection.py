"""
SQL Injection detector using compiled regex patterns.
"""

import re
import logging
import urllib.parse
from typing import Dict

from backend.detection.patterns import SQL_INJECTION_PATTERNS, CRITICAL_PATTERNS

logger = logging.getLogger(__name__)

_COMPILED = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in SQL_INJECTION_PATTERNS]
_CRITICAL = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in CRITICAL_PATTERNS["SQL_INJECTION"]]


class SQLInjectionDetector:
    """Detect SQL injection attempts in request path / query string."""

    def detect(self, request_path: str, method: str = "GET") -> Dict:
        """
        Analyse *request_path* for SQL injection patterns.

        Returns a result dict with keys:
          detected (bool), attack_type, severity, pattern, confidence
        """
        # Decode URL encoding layers
        target = _decode(request_path)

        matched_pattern = None
        is_critical = False

        for crit in _CRITICAL:
            m = crit.search(target)
            if m:
                matched_pattern = crit.pattern
                is_critical = True
                break

        if not matched_pattern:
            for compiled in _COMPILED:
                m = compiled.search(target)
                if m:
                    matched_pattern = compiled.pattern
                    break

        if not matched_pattern:
            return {"detected": False, "attack_type": "SQL_INJECTION"}

        severity = "CRITICAL" if is_critical else "HIGH"
        confidence = 0.95 if is_critical else 0.80

        return {
            "detected": True,
            "attack_type": "SQL_INJECTION",
            "severity": severity,
            "pattern": matched_pattern,
            "confidence": confidence,
            "details": f"SQL injection pattern matched in: {request_path[:200]}",
            "recommended_action": "BLOCK_IP",
        }


def _decode(text: str) -> str:
    """Decode URL encoding (including double encoding)."""
    try:
        decoded = urllib.parse.unquote_plus(text)
        # Second pass for double-encoded payloads
        decoded = urllib.parse.unquote_plus(decoded)
        return decoded
    except Exception:
        return text
