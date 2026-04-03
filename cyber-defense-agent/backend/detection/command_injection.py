"""
Command injection detector.
"""

import re
import logging
import urllib.parse
from typing import Dict

from backend.detection.patterns import COMMAND_INJECTION_PATTERNS

logger = logging.getLogger(__name__)

_COMPILED = [re.compile(p, re.IGNORECASE) for p in COMMAND_INJECTION_PATTERNS]


class CommandInjectionDetector:
    """Detect OS command injection in request paths."""

    def detect(self, path: str) -> Dict:
        target = _decode(path)

        for compiled in _COMPILED:
            if compiled.search(target):
                return {
                    "detected": True,
                    "attack_type": "COMMAND_INJECTION",
                    "severity": "CRITICAL",
                    "pattern": compiled.pattern,
                    "confidence": 0.90,
                    "details": f"Command injection pattern: {path[:200]}",
                    "recommended_action": "BLOCK_IP",
                }

        return {"detected": False, "attack_type": "COMMAND_INJECTION"}


def _decode(text: str) -> str:
    try:
        return urllib.parse.unquote_plus(urllib.parse.unquote_plus(text))
    except Exception:
        return text
