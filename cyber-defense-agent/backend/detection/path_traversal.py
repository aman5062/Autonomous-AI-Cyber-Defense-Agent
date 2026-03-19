import re
import logging
from urllib.parse import unquote_plus
from backend.detection.patterns import PATH_TRAVERSAL_PATTERNS, SENSITIVE_FILES

logger = logging.getLogger(__name__)

_COMPILED = [re.compile(p, re.IGNORECASE) for p in PATH_TRAVERSAL_PATTERNS]


class PathTraversalDetector:
    def detect(self, path: str) -> dict:
        decoded = unquote_plus(path)

        # Check sensitive file access
        for sf in SENSITIVE_FILES:
            if sf.lower() in decoded.lower():
                return {
                    "detected": True,
                    "attack_type": "PATH_TRAVERSAL",
                    "severity": "CRITICAL",
                    "confidence": 0.99,
                    "pattern": sf,
                    "recommended_action": "BLOCK_IP",
                    "details": f"Sensitive file access attempt: {sf}",
                }

        # Check traversal patterns
        for pattern in _COMPILED:
            if pattern.search(decoded):
                return {
                    "detected": True,
                    "attack_type": "PATH_TRAVERSAL",
                    "severity": "HIGH",
                    "confidence": 0.90,
                    "pattern": pattern.pattern,
                    "recommended_action": "BLOCK_IP",
                    "details": f"Path traversal pattern in: {path[:100]}",
                }

        return {"detected": False}
