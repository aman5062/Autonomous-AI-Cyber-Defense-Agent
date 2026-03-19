import asyncio
import logging
import os
import time
from pathlib import Path
from typing import AsyncGenerator

from backend.monitoring.log_parser import NginxLogParser

logger = logging.getLogger(__name__)


class LogCollector:
    """Tails NGINX access log in real-time and yields parsed requests."""

    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.parser = NginxLogParser()
        self._running = False

    async def tail_logs_async(self) -> AsyncGenerator[dict, None]:
        """Async generator that yields parsed log entries as they arrive."""
        self._running = True

        # Wait for log file to exist
        while not self.log_path.exists():
            logger.info(f"Waiting for log file: {self.log_path}")
            await asyncio.sleep(5)

        logger.info(f"Tailing log file: {self.log_path}")

        with open(self.log_path, "r") as f:
            # Seek to end on startup
            f.seek(0, 2)

            while self._running:
                line = f.readline()
                if line:
                    parsed = self.parser.parse(line.strip())
                    if parsed:
                        yield parsed
                else:
                    await asyncio.sleep(0.1)

    def stop(self):
        self._running = False
