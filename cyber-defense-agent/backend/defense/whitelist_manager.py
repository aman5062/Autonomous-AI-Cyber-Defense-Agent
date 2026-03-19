import ipaddress
import logging
from pathlib import Path
from backend.config import settings

logger = logging.getLogger(__name__)


class WhitelistManager:
    def __init__(self):
        self._static: list = list(settings.WHITELIST)
        self._networks: list = []
        self._load_file()

    def _load_file(self):
        path = Path(settings.WHITELIST_PATH)
        if not path.exists():
            return
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    if "/" in line:
                        self._networks.append(ipaddress.ip_network(line, strict=False))
                    else:
                        self._static.append(line)
                except ValueError:
                    logger.warning(f"Invalid whitelist entry: {line}")

    def is_whitelisted(self, ip: str) -> bool:
        if ip in self._static:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._networks)
        except ValueError:
            return False

    def add(self, ip: str):
        if ip not in self._static:
            self._static.append(ip)
            logger.info(f"Added {ip} to whitelist.")
