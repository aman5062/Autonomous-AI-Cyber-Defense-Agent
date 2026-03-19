import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_PATTERNS_PATH = Path("/app/config/attack_patterns.json")


def load_patterns() -> dict:
    if _PATTERNS_PATH.exists():
        with open(_PATTERNS_PATH) as f:
            return json.load(f)
    logger.warning("attack_patterns.json not found, using defaults")
    return {}


PATTERNS = load_patterns()

SQL_PATTERNS = PATTERNS.get("sql_injection", [])
XSS_PATTERNS = PATTERNS.get("xss", [])
PATH_TRAVERSAL_PATTERNS = PATTERNS.get("path_traversal", [])
COMMAND_INJECTION_PATTERNS = PATTERNS.get("command_injection", [])
SENSITIVE_FILES = PATTERNS.get("sensitive_files", [])
