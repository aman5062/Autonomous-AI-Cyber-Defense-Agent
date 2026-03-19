import re
import logging
from urllib.parse import unquote_plus
from backend.detection.patterns import SQL_PATTERNS

logger = logging.getLogger(__name__)

_CRITICAL_KEYWORDS = re.compile(
    r"\b(DROP|DELETE|EXEC|EXECUTE|UNION\s+SELECT|xp_cmdshell|LOAD_FILE|INTO\s+OUTFILE|BENCHMARK|SLEEP|WAITFOR)\b",
    re.IGNORECASE,
)
_HIGH_KEYWORDS = re.compile(
    r"(\bOR\b.{0,20}=|admin'--|' OR '1'='1|1=1)", re.IGNORECASE
)

_COMPILED = [re.compile(p, re.IGNORECASE) for p in SQL_PATTERNS]


class SQLInjectionDetector:
    def detect(self, path: str, method: str = "GET") -> dict:
        decoded = unquote_plus(path)
        target = decoded.lower()

        matched_pattern = None
        for pattern in _COMPILED:
            if pattern.search(decoded):
                matched_pattern = pattern.pattern
                break

        if not matched_pattern:
            return {"detected": False}

        if _CRITICAL_KEYWORDS.search(decoded):
            severity = "CRITICAL"
        elif _HIGH_KEYWORDS.search(decoded):
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        return {
            "detected": True,
            "attack_type": "SQL_INJECTION",
            "severity": severity,
            "pattern": matched_pattern,
            "confidence": 0.95,
            "recommended_action": "BLOCK_IP",
            "details": f"SQL injection pattern matched in path: {path[:100]}",
        }
