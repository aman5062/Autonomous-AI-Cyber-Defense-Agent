"""
Parse NGINX combined-format access log lines into structured dictionaries.
"""

import re
import logging
from datetime import datetime
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# NGINX combined log format pattern
_LOG_RE = re.compile(
    r'(?P<ip>[\da-fA-F:.]+)'          # IP (IPv4 or IPv6)
    r'\s+-\s+-\s+'                    # ident / auth
    r'\[(?P<timestamp>[^\]]+)\]'      # [timestamp]
    r'\s+"(?P<method>\w+)'            # "METHOD
    r'\s+(?P<path>[^\s"]+)'           # /path?query
    r'\s+HTTP/[\d.]+"'                # HTTP/1.1"
    r'\s+(?P<status>\d+)'             # status code
    r'\s+(?P<size>\d+|-)'             # bytes sent
    r'\s+"(?P<referrer>[^"]*)"'       # "referrer"
    r'\s+"(?P<user_agent>[^"]*)"'     # "user_agent"
)


class NginxLogParser:
    """Parse NGINX access log lines into structured dicts."""

    def parse(self, log_line: str) -> Optional[Dict]:
        """
        Parse a single NGINX log line.

        Returns a dict on success or None if the line is unparseable.
        """
        log_line = log_line.strip()
        if not log_line:
            return None
        m = _LOG_RE.match(log_line)
        if not m:
            logger.debug("Unparseable log line: %s", log_line[:120])
            return None

        size_raw = m.group("size")
        return {
            "ip": m.group("ip"),
            "timestamp": m.group("timestamp"),
            "method": m.group("method"),
            "path": m.group("path"),
            "status": int(m.group("status")),
            "size": int(size_raw) if size_raw != "-" else 0,
            "referrer": m.group("referrer"),
            "user_agent": m.group("user_agent"),
            "raw_log": log_line,
        }

    def parse_timestamp(self, ts: str) -> Optional[datetime]:
        """Parse NGINX timestamp string into a datetime object."""
        try:
            return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return None
