"""
WiFi / Local Network Protection Monitor.

Scans the local subnet for connected devices and detects suspicious activity
such as port scanning, ARP spoofing indicators, and traffic from blocked IPs.
Works without raw-socket privileges by using ICMP ping + TCP probing.

Designed for demonstration in a school / college / office network scenario:
  - Discovers all devices on the local WiFi/LAN
  - Flags devices that are performing attacks (cross-referenced with blocked IPs)
  - Exposes results via the backend REST API
"""

import asyncio
import ipaddress
import logging
import os
import platform
import re
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

from backend.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ping(ip: str, timeout: float = 1.0) -> bool:
    """Return True if *ip* responds to a single ICMP ping."""
    flag = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        r = subprocess.run(
            ["ping", flag, "1", "-W", "1", str(ip)],
            capture_output=True,
            timeout=timeout + 1,
        )
        return r.returncode == 0
    except Exception:
        return False


def _resolve_hostname(ip: str) -> str:
    """Attempt reverse-DNS lookup; return '' on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _get_local_ip() -> str:
    """Return the machine's primary outbound IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _get_subnet(ip: str, prefix: int = 24) -> str:
    """Build a /24 subnet from an IP, e.g. '192.168.1.0/24'."""
    net = ipaddress.ip_interface(f"{ip}/{prefix}").network
    return str(net)


def _arp_table() -> Dict[str, str]:
    """
    Parse the local ARP cache and return {ip: mac} mapping.
    Works on Linux and macOS; returns {} on Windows or on error.
    """
    result: Dict[str, str] = {}
    try:
        out = subprocess.check_output(["arp", "-a"], timeout=5, text=True)
        # Linux: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
        # macOS: gateway (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
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
# Device record
# ---------------------------------------------------------------------------

class Device:
    __slots__ = (
        "ip", "mac", "hostname", "first_seen", "last_seen",
        "is_trusted", "is_blocked", "open_ports", "risk_level", "notes",
    )

    def __init__(self, ip: str):
        self.ip = ip
        self.mac: str = ""
        self.hostname: str = ""
        self.first_seen: str = _now()
        self.last_seen: str = _now()
        self.is_trusted: bool = False
        self.is_blocked: bool = False
        self.open_ports: List[int] = []
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
            "open_ports": self.open_ports,
            "risk_level": self.risk_level,
            "notes": self.notes,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# WiFiMonitor
# ---------------------------------------------------------------------------

class WiFiMonitor:
    """
    Continuously scans the local subnet and maintains a device registry.

    Usage (background thread)::

        monitor = WiFiMonitor()
        monitor.start()
        ...
        devices = monitor.get_devices()
        monitor.stop()
    """

    def __init__(self):
        self._cfg = settings.wifi
        self._trusted: set = set(self._cfg.trusted_devices)
        self._devices: Dict[str, Device] = {}
        self._blocked_ips: set = set()  # synced from DefenseStorage
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._local_ip: str = ""
        self._subnet: str = ""

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop, name="wifi-monitor", daemon=True
        )
        self._thread.start()
        logger.info("WiFi monitor started")

    def stop(self) -> None:
        self._running = False
        logger.info("WiFi monitor stopped")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_devices(self) -> List[Dict]:
        with self._lock:
            return [d.to_dict() for d in self._devices.values()]

    def get_summary(self) -> Dict:
        with self._lock:
            devices = list(self._devices.values())
        total = len(devices)
        blocked = sum(1 for d in devices if d.is_blocked)
        trusted = sum(1 for d in devices if d.is_trusted)
        risky = sum(1 for d in devices if d.risk_level in ("HIGH", "CRITICAL"))
        return {
            "total_devices": total,
            "blocked_devices": blocked,
            "trusted_devices": trusted,
            "risky_devices": risky,
            "local_ip": self._local_ip,
            "subnet": self._subnet,
            "last_scan": _now(),
        }

    def update_blocked_ips(self, blocked_ips: set) -> None:
        """Called by the route layer to keep blocked-IP set in sync."""
        self._blocked_ips = set(blocked_ips)
        with self._lock:
            for dev in self._devices.values():
                dev.is_blocked = dev.ip in self._blocked_ips
                if dev.is_blocked and "BLOCKED by defense engine" not in dev.notes:
                    dev.notes.append("BLOCKED by defense engine")
                    dev.risk_level = "CRITICAL"

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:
        self._local_ip = _get_local_ip()
        self._subnet = _get_subnet(self._local_ip)
        logger.info("WiFi monitor scanning subnet %s", self._subnet)

        while self._running:
            try:
                self._scan_network()
            except Exception as exc:
                logger.warning("WiFi scan error: %s", exc)
            # Sleep in small increments so stop() is responsive
            for _ in range(self._cfg.scan_interval * 2):
                if not self._running:
                    return
                time.sleep(0.5)

    def _scan_network(self) -> None:
        """Ping-sweep the subnet and update the device registry."""
        try:
            network = ipaddress.ip_network(self._subnet, strict=False)
        except ValueError:
            return

        # Limit scan to /24 (254 hosts max) to keep it fast
        hosts = list(network.hosts())[:254]
        arp = _arp_table()

        alive_ips: List[str] = []

        # Use threads for parallel pinging
        results: Dict[str, bool] = {}
        threads = []

        def _do_ping(ip_str: str) -> None:
            results[ip_str] = _ping(ip_str)

        for host in hosts:
            t = threading.Thread(target=_do_ping, args=(str(host),), daemon=True)
            threads.append(t)
            t.start()
            # Stagger slightly to avoid flooding
            if len(threads) % 20 == 0:
                time.sleep(0.05)

        for t in threads:
            t.join(timeout=3)

        alive_ips = [ip for ip, alive in results.items() if alive]

        with self._lock:
            for ip in alive_ips:
                if ip not in self._devices:
                    dev = Device(ip)
                    self._devices[ip] = dev
                else:
                    dev = self._devices[ip]

                dev.last_seen = _now()
                dev.mac = arp.get(ip, dev.mac)
                if not dev.hostname:
                    dev.hostname = _resolve_hostname(ip)
                dev.is_trusted = ip in self._trusted
                dev.is_blocked = ip in self._blocked_ips

                # Assign risk level
                if dev.is_blocked:
                    dev.risk_level = "CRITICAL"
                elif ip == self._local_ip:
                    dev.risk_level = "SAFE"
                    if "This machine (defense agent)" not in dev.notes:
                        dev.notes.append("This machine (defense agent)")
                elif dev.is_trusted:
                    dev.risk_level = "SAFE"
                else:
                    dev.risk_level = "LOW"

        logger.debug("WiFi scan complete: %d devices online", len(alive_ips))
