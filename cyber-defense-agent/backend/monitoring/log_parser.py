import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# NGINX combined log format
LOG_PATTERN = re.compile(
    r'(?P<ip>[\d\.]+) - (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<path>[^\s"]+) HTTP/[\d\.]+" '
    r'(?P<status>\d+) (?P<size>\d+|-) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
)


class NginxLogParser:
    """Parses NGINX combined log format into structured dicts."""

    def parse(self, log_line: str) -> Optional[dict]:
        if not log_line:
            return None

        match = LOG_PATTERN.match(log_line)
        if not match:
            logger.debug(f"Could not parse log line: {log_line[:80]}")
            return None

        size_raw = match.group("size")
        return {
            "ip": match.group("ip"),
            "user": match.group("user"),
            "timestamp": match.group("timestamp"),
            "method": match.group("method"),
            "path": match.group("path"),
            "status": int(match.group("status")),
            "size": int(size_raw) if size_raw != "-" else 0,
            "referrer": match.group("referrer"),
            "user_agent": match.group("user_agent"),
            "raw_log": log_line,
        }
