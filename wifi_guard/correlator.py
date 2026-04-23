"""
Backend Correlator — periodically syncs blocked IPs from the
main Cyber Defense backend and feeds them to the network scanner.
"""

import logging
import threading
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)


class BackendCorrelator:
    """
    Polls the main backend's ``/api/defense/blocked-ips`` endpoint
    every *interval* seconds and calls *on_update(ips)* with the
    fresh set of blocked IP strings.
    """

    def __init__(
        self,
        backend_url: str,
        on_update,
        interval: int = 10,
    ):
        self._url = backend_url.rstrip("/") + "/api/defense/blocked-ips"
        self._on_update = on_update
        self._interval = interval
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name="backend-correlator", daemon=True
        )
        self._thread.start()
        logger.info("Backend correlator started  url=%s", self._url)

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        while self._running:
            try:
                r = requests.get(self._url, timeout=5)
                if r.status_code == 200:
                    data = r.json()
                    ips = {item["ip"] for item in data.get("blocked_ips", [])}
                    self._on_update(ips)
            except Exception as exc:
                logger.debug("Correlator sync failed: %s", exc)

            for _ in range(self._interval * 2):
                if not self._running:
                    return
                time.sleep(0.5)
