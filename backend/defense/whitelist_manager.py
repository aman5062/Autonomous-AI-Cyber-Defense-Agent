"""
Whitelist manager – tracks IPs that should never be blocked.
"""

import ipaddress
import logging
from pathlib import Path
from typing import Set

from backend.config import settings, BASE_DIR

logger = logging.getLogger(__name__)

_WHITELIST_FILE = BASE_DIR / "config" / "whitelist.txt"

# Always-safe addresses
_ALWAYS_SAFE = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}


class WhitelistManager:
    """In-memory + file-backed IP whitelist."""

    def __init__(self):
        self._whitelist: Set[str] = set(_ALWAYS_SAFE)
        self._whitelist.update(settings.defense.whitelist)
        self._load_from_file()

    def is_whitelisted(self, ip: str) -> bool:
        if ip in self._whitelist:
            return True
        # Only block truly loopback / link-local (NOT general private ranges —
        # private IPs are valid attacker sources in internal networks)
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_loopback or addr.is_link_local
        except ValueError:
            return False

    def add(self, ip: str, reason: str = ""):
        self._whitelist.add(ip)
        self._persist()
        logger.info("Added %s to whitelist: %s", ip, reason)

    def remove(self, ip: str):
        self._whitelist.discard(ip)
        self._persist()

    def list_all(self):
        return sorted(self._whitelist)

    def _load_from_file(self):
        if _WHITELIST_FILE.exists():
            for line in _WHITELIST_FILE.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    self._whitelist.add(line)

    def _persist(self):
        try:
            _WHITELIST_FILE.parent.mkdir(parents=True, exist_ok=True)
            lines = ["# Auto-generated whitelist"] + sorted(self._whitelist)
            _WHITELIST_FILE.write_text("\n".join(lines) + "\n")
        except OSError as exc:
            logger.warning("Could not write whitelist file: %s", exc)
