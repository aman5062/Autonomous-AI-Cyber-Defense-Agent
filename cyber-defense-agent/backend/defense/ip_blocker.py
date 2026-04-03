"""
IP Blocker – wraps iptables to block/unblock IPs.
Falls back to a simulated (dry-run) mode when iptables is unavailable
(e.g. development machines, containers without CAP_NET_ADMIN).
"""

import ipaddress
import logging
import re
import subprocess
from typing import List

from backend.config import settings

logger = logging.getLogger(__name__)


def _run(cmd: List[str], dry_run: bool = False) -> bool:
    """Execute a shell command, returning True on success."""
    if dry_run:
        logger.info("[DRY-RUN] Would execute: %s", " ".join(cmd))
        return True
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            logger.warning("Command failed (%s): %s", result.returncode, result.stderr)
        return result.returncode == 0
    except FileNotFoundError:
        logger.warning("iptables not found – switching to dry-run mode")
        return False
    except subprocess.TimeoutExpired:
        logger.error("iptables command timed out: %s", " ".join(cmd))
        return False
    except Exception as exc:  # noqa: BLE001
        logger.error("iptables error: %s", exc)
        return False


class IPBlocker:
    """
    Block / unblock IP addresses via iptables.

    When *dry_run* is True (or iptables is unavailable) all operations
    are logged but no real firewall rules are created.
    """

    def __init__(self):
        self._dry_run = settings.defense.dry_run_mode
        self._simulated_blocks: set = set()  # for dry-run tracking

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def block_ip(self, ip: str, reason: str = "") -> bool:
        if not self._valid_ip(ip):
            logger.error("Invalid IP address: %s", ip)
            return False

        if self.is_blocked(ip):
            logger.debug("IP %s already blocked", ip)
            return True

        logger.info("Blocking IP %s – reason: %s", ip, reason)
        success = _run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            dry_run=self._dry_run,
        )
        if success or self._dry_run:
            self._simulated_blocks.add(ip)
        return success or self._dry_run

    def unblock_ip(self, ip: str) -> bool:
        if not self._valid_ip(ip):
            return False
        if not self.is_blocked(ip):
            logger.debug("IP %s was not blocked", ip)
            return True

        logger.info("Unblocking IP %s", ip)
        success = _run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            dry_run=self._dry_run,
        )
        if success or self._dry_run:
            self._simulated_blocks.discard(ip)
        return success or self._dry_run

    def is_blocked(self, ip: str) -> bool:
        if ip in self._simulated_blocks:
            return True
        if self._dry_run:
            return False
        # Check actual iptables rules
        try:
            result = subprocess.run(
                ["sudo", "iptables", "-L", "INPUT", "-n"],
                capture_output=True, text=True, timeout=10,
            )
            return ip in result.stdout
        except Exception:
            return ip in self._simulated_blocks

    def list_blocked_ips(self) -> List[str]:
        """Return list of IPs currently blocked via iptables DROP rules."""
        if self._dry_run:
            return sorted(self._simulated_blocks)
        try:
            result = subprocess.run(
                ["sudo", "iptables", "-L", "INPUT", "-n", "--line-numbers"],
                capture_output=True, text=True, timeout=10,
            )
            ips = re.findall(
                r"DROP\s+all\s+--\s+([\d.]+)",
                result.stdout,
            )
            # Merge with simulated (manual) blocks
            return sorted(set(ips) | self._simulated_blocks)
        except Exception as exc:
            logger.warning("Could not list iptables rules: %s", exc)
            return sorted(self._simulated_blocks)

    def flush_all(self):
        """Remove ALL INPUT DROP rules (emergency use only)."""
        logger.warning("Flushing all INPUT rules!")
        _run(["sudo", "iptables", "-F", "INPUT"], dry_run=self._dry_run)
        self._simulated_blocks.clear()

    # ------------------------------------------------------------------

    @staticmethod
    def _valid_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
