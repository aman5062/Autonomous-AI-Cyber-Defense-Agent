"""
Network Scanner — discovers devices on the local subnet.

Uses ICMP ping-sweep + ARP cache + reverse-DNS. No raw socket
privileges required; works inside a Docker container with
--network=host or a host-mode network.
"""

import ipaddress
import logging
import platform
import re
import socket
import subprocess
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ping(ip: str, timeout: float = 1.0) -> bool:
    """Return True if *ip* responds to a single ICMP ping."""
    flag = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        r = subprocess.run(
            ["ping", flag, "1", "-W", "1", str(ip)],
            capture_output=True,
            timeout=timeout + 2,
        )
        return r.returncode == 0
    except Exception:
        return False


def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def get_subnet(ip: str, prefix: int = 24) -> str:
    net = ipaddress.ip_interface(f"{ip}/{prefix}").network
    return str(net)


def read_arp_table() -> Dict[str, str]:
    """Return {ip: mac} from the local ARP cache."""
    result: Dict[str, str] = {}
    try:
        out = subprocess.check_output(["arp", "-a"], timeout=5, text=True)
        for line in out.splitlines():
            m = re.search(
                r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-fA-F:]{11,17})",
                line,
            )
            if m:
                result[m.group(1)] = m.group(2).lower()
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Device model
# ---------------------------------------------------------------------------

class Device:
    """Represents a single network-connected device."""

    def __init__(self, ip: str):
        self.ip: str = ip
        self.mac: str = ""
        self.hostname: str = ""
        self.first_seen: str = _now()
        self.last_seen: str = _now()
        self.is_trusted: bool = False
        self.is_blocked: bool = False
        self.risk_level: str = "UNKNOWN"
        self.notes: List[str] = []

    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "is_trusted": self.is_trusted,
            "is_blocked": self.is_blocked,
            "risk_level": self.risk_level,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# NetworkScanner
# ---------------------------------------------------------------------------

class NetworkScanner:
    """
    Ping-sweeps the local /24 subnet and maintains a device registry.

    Runs continuously in a background thread.  Call ``start()`` once,
    then read ``devices`` and ``summary`` from any thread.
    """

    def __init__(self, trusted_ips: List[str] = None, scan_interval: int = 30):
        self._trusted: set = set(trusted_ips or [])
        self._scan_interval = scan_interval
        self._devices: Dict[str, Device] = {}
        self._blocked_ips: set = set()
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.local_ip: str = ""
        self.subnet: str = ""
        self.last_scan: str = ""

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name="network-scanner", daemon=True
        )
        self._thread.start()
        logger.info("Network scanner started")

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------
    # Public reads
    # ------------------------------------------------------------------

    @property
    def devices(self) -> List[Dict]:
        with self._lock:
            return [d.to_dict() for d in self._devices.values()]

    @property
    def summary(self) -> Dict:
        with self._lock:
            devs = list(self._devices.values())
        return {
            "total_devices": len(devs),
            "blocked_devices": sum(1 for d in devs if d.is_blocked),
            "trusted_devices": sum(1 for d in devs if d.is_trusted),
            "risky_devices": sum(1 for d in devs if d.risk_level in ("HIGH", "CRITICAL")),
            "local_ip": self.local_ip,
            "subnet": self.subnet,
            "last_scan": self.last_scan,
        }

    def set_blocked_ips(self, ips: set) -> None:
        """Update the blocked-IP set (called after syncing with the defense backend)."""
        self._blocked_ips = set(ips)
        with self._lock:
            for dev in self._devices.values():
                was_blocked = dev.is_blocked
                dev.is_blocked = dev.ip in self._blocked_ips
                if dev.is_blocked:
                    dev.risk_level = "CRITICAL"
                    if "Blocked by AI defense engine" not in dev.notes:
                        dev.notes.append("Blocked by AI defense engine")

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        import time
        self.local_ip = get_local_ip()
        self.subnet = get_subnet(self.local_ip)
        logger.info("Scanning subnet %s  (interval=%ds)", self.subnet, self._scan_interval)

        while self._running:
            try:
                self._scan()
            except Exception as exc:
                logger.warning("Scan error: %s", exc)

            for _ in range(self._scan_interval * 2):
                if not self._running:
                    return
                time.sleep(0.5)

    def _scan(self) -> None:
        try:
            network = ipaddress.ip_network(self.subnet, strict=False)
        except ValueError:
            return

        hosts = list(network.hosts())[:254]
        arp = read_arp_table()

        # Parallel ping sweep
        alive: Dict[str, bool] = {}

        def _do_ping(ip_str: str) -> None:
            alive[ip_str] = _ping(ip_str)

        threads = []
        for host in hosts:
            t = threading.Thread(target=_do_ping, args=(str(host),), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=4)

        alive_ips = [ip for ip, up in alive.items() if up]

        with self._lock:
            for ip in alive_ips:
                if ip not in self._devices:
                    self._devices[ip] = Device(ip)
                dev = self._devices[ip]
                dev.last_seen = _now()
                dev.mac = arp.get(ip, dev.mac)
                if not dev.hostname:
                    dev.hostname = _resolve_hostname(ip)
                dev.is_trusted = ip in self._trusted
                dev.is_blocked = ip in self._blocked_ips

                if dev.is_blocked:
                    dev.risk_level = "CRITICAL"
                elif ip == self.local_ip:
                    dev.risk_level = "SAFE"
                    if "WiFi Guard (this machine)" not in dev.notes:
                        dev.notes.append("WiFi Guard (this machine)")
                elif dev.is_trusted:
                    dev.risk_level = "SAFE"
                else:
                    dev.risk_level = "LOW"

        self.last_scan = _now()
        logger.debug("Scan complete: %d devices alive", len(alive_ips))
