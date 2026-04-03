"""
Real-time log collector – tails NGINX access.log and yields new lines.
Also generates synthetic log entries for demonstration when no real log exists.
"""

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import AsyncGenerator, Callable, Optional

from backend.config import settings

logger = logging.getLogger(__name__)


class LogCollector:
    """Tail a log file and yield new lines as they appear."""

    def __init__(self, log_path: Optional[str] = None):
        self.log_path = Path(log_path or settings.monitoring.nginx_log_path)
        self._running = False

    # ------------------------------------------------------------------
    # Async interface
    # ------------------------------------------------------------------

    async def tail_logs_async(self) -> AsyncGenerator[str, None]:
        """Async generator that yields new log lines in real-time."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.touch()

        with open(self.log_path, "r", encoding="utf-8", errors="replace") as fh:
            # Seek to end so we only get new lines
            fh.seek(0, 2)
            while True:
                line = fh.readline()
                if line:
                    yield line.rstrip("\n")
                else:
                    await asyncio.sleep(settings.monitoring.poll_interval)

    async def start_monitoring(self, callback: Callable[[str], None]):
        """Start monitoring loop, calling *callback* for each new line."""
        self._running = True
        async for line in self.tail_logs_async():
            if not self._running:
                break
            try:
                await asyncio.coroutine(callback)(line) if asyncio.iscoroutinefunction(callback) \
                    else callback(line)
            except Exception as exc:  # noqa: BLE001
                logger.error("Log callback error: %s", exc)

    def stop(self):
        self._running = False

    # ------------------------------------------------------------------
    # Synchronous tail (used in tests / simple scripts)
    # ------------------------------------------------------------------

    def tail_logs_sync(self):
        """Generator that yields new log lines (blocking, for tests)."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.touch()

        with open(self.log_path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, 2)
            while True:
                line = fh.readline()
                if line:
                    yield line.rstrip("\n")
                else:
                    time.sleep(settings.monitoring.poll_interval)


class SimulatedLogCollector:
    """
    Generates synthetic NGINX log entries for demo / development purposes.
    Used when no real NGINX instance is present.
    """

    DEMO_ENTRIES = [
        '192.168.1.100 - - [{ts}] "GET /login?user=\' OR \'1\'=\'1-- HTTP/1.1" 401 512 "-" "sqlmap/1.7"',
        '10.0.0.25 - - [{ts}] "POST /login HTTP/1.1" 401 256 "-" "python-requests/2.31"',
        '10.0.0.25 - - [{ts}] "POST /login HTTP/1.1" 401 256 "-" "python-requests/2.31"',
        '10.0.0.25 - - [{ts}] "POST /login HTTP/1.1" 401 256 "-" "python-requests/2.31"',
        '10.0.0.25 - - [{ts}] "POST /login HTTP/1.1" 401 256 "-" "python-requests/2.31"',
        '10.0.0.25 - - [{ts}] "POST /login HTTP/1.1" 401 256 "-" "python-requests/2.31"',
        '172.16.0.50 - - [{ts}] "GET /../../../../etc/passwd HTTP/1.1" 400 128 "-" "curl/7.68.0"',
        '192.168.2.200 - - [{ts}] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
        '8.8.8.8 - - [{ts}] "GET /index.html HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',
        '192.168.1.1 - - [{ts}] "GET /api/health HTTP/1.1" 200 64 "-" "curl/7.68.0"',
        '203.0.113.10 - - [{ts}] "GET /admin?cmd=ls%20/etc HTTP/1.1" 403 256 "-" "Nikto/2.1.6"',
    ]

    def __init__(self, interval: float = 2.0):
        self.interval = interval
        self._running = False

    async def tail_logs_async(self) -> AsyncGenerator[str, None]:
        self._running = True
        idx = 0
        while self._running:
            ts = time.strftime("%d/%b/%Y:%H:%M:%S +0000")
            yield self.DEMO_ENTRIES[idx % len(self.DEMO_ENTRIES)].format(ts=ts)
            idx += 1
            await asyncio.sleep(self.interval)

    def stop(self):
        self._running = False
