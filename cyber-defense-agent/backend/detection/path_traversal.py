"""
Path traversal / directory traversal detector.
"""

import re
import logging
import urllib.parse
from typing import Dict

from backend.detection.patterns import PATH_TRAVERSAL_PATTERNS, SENSITIVE_FILES

logger = logging.getLogger(__name__)

_COMPILED = [re.compile(p, re.IGNORECASE) for p in PATH_TRAVERSAL_PATTERNS]
_SENSITIVE = [re.compile(re.escape(f), re.IGNORECASE) for f in SENSITIVE_FILES]


class PathTraversalDetector:
    """Detect path traversal / directory traversal attacks."""

    def detect(self, path: str) -> Dict:
        target = _decode(path)

        # Check for sensitive file targets first (highest confidence)
        for sf in _SENSITIVE:
            if sf.search(target):
                return {
                    "detected": True,
                    "attack_type": "PATH_TRAVERSAL",
                    "severity": "CRITICAL",
                    "pattern": sf.pattern,
                    "confidence": 0.97,
                    "details": f"Sensitive file access attempt: {path[:200]}",
                    "recommended_action": "BLOCK_IP",
                }

        for compiled in _COMPILED:
            if compiled.search(target):
                return {
                    "detected": True,
                    "attack_type": "PATH_TRAVERSAL",
                    "severity": "HIGH",
                    "pattern": compiled.pattern,
                    "confidence": 0.85,
                    "details": f"Path traversal pattern: {path[:200]}",
                    "recommended_action": "BLOCK_IP",
                }

        return {"detected": False, "attack_type": "PATH_TRAVERSAL"}


def _decode(text: str) -> str:
    try:
        decoded = urllib.parse.unquote_plus(text)
        decoded = urllib.parse.unquote_plus(decoded)
        return decoded
    except Exception:
        return text
