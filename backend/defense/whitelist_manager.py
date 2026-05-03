"""
Whitelist manager – tracks IPs that should never be blocked.
"""

import ipaddress
import logging
from pathlib import Path
from typing import Set, List

from backend.config import settings, BASE_DIR

logger = logging.getLogger(__name__)

_WHITELIST_FILE = BASE_DIR / "config" / "whitelist.txt"

# Always-safe addresses
_ALWAYS_SAFE = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}

# Always-safe networks — only Docker internals and loopback
# NOTE: 192.168.x.x and 10.x.x.x are intentionally NOT whitelisted so that
# devices on the local WiFi/LAN can be blocked by the demo and defense engine.
# The Docker bridge range (172.16/12) is kept so the system never blocks itself.
_ALWAYS_SAFE_NETWORKS = [
    ipaddress.ip_network("172.16.0.0/12"),   # Docker default bridge range
]


class WhitelistManager:
    """In-memory + file-backed IP whitelist with CIDR support."""

    def __init__(self):
        self._whitelist: Set[str] = set(_ALWAYS_SAFE)
        self._networks: List[ipaddress.IPv4Network] = list(_ALWAYS_SAFE_NETWORKS)
        self._whitelist.update(settings.defense.whitelist)
        self._load_from_file()

    def is_whitelisted(self, ip: str) -> bool:
        if ip in self._whitelist:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            # Always allow loopback and link-local
            if addr.is_loopback or addr.is_link_local:
                return True
            # Check CIDR networks
            for net in self._networks:
                if addr in net:
                    return True
        except ValueError:
            pass
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
                if not line or line.startswith("#"):
                    continue
                # Try CIDR network
                if "/" in line:
                    try:
                        self._networks.append(ipaddress.ip_network(line, strict=False))
                        continue
                    except ValueError:
                        pass
                self._whitelist.add(line)

    def _persist(self):
        try:
            _WHITELIST_FILE.parent.mkdir(parents=True, exist_ok=True)
            lines = ["# Auto-generated whitelist"] + sorted(self._whitelist)
            _WHITELIST_FILE.write_text("\n".join(lines) + "\n")
        except OSError as exc:
            logger.warning("Could not write whitelist file: %s", exc)
