import subprocess
import logging
import re

logger = logging.getLogger(__name__)

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class IPBlocker:
    """Manages iptables rules for IP blocking."""

    def block_ip(self, ip: str, reason: str = "") -> bool:
        if not self._valid(ip):
            logger.error(f"Invalid IP: {ip}")
            return False
        try:
            # Avoid duplicate rules
            if self.is_blocked(ip):
                logger.info(f"IP {ip} already blocked.")
                return True
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
            logger.info(f"Blocked IP: {ip} | Reason: {reason}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables block failed for {ip}: {e.stderr.decode()}")
            return False
        except FileNotFoundError:
            logger.warning("iptables not available (running in simulation mode).")
            return True  # Simulate success in non-Linux envs

    def unblock_ip(self, ip: str) -> bool:
        if not self._valid(ip):
            return False
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
            logger.info(f"Unblocked IP: {ip}")
            return True
        except subprocess.CalledProcessError:
            logger.warning(f"iptables unblock failed for {ip} (may not be blocked).")
            return False
        except FileNotFoundError:
            logger.warning("iptables not available.")
            return True

    def is_blocked(self, ip: str) -> bool:
        try:
            result = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def list_blocked(self) -> list:
        try:
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-n"],
                capture_output=True, text=True
            )
            blocked = []
            for line in result.stdout.splitlines():
                if "DROP" in line:
                    parts = line.split()
                    for part in parts:
                        if _IP_RE.match(part):
                            blocked.append(part)
            return blocked
        except FileNotFoundError:
            return []

    def _valid(self, ip: str) -> bool:
        return bool(_IP_RE.match(ip))
