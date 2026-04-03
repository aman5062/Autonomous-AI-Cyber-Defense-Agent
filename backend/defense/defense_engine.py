"""
Defense Automation Engine – decides and executes defensive actions.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List

from backend.config import settings
from backend.defense.ip_blocker import IPBlocker
from backend.defense.rate_limiter import RateLimiter
from backend.defense.whitelist_manager import WhitelistManager
from backend.defense.unblock_scheduler import UnblockScheduler
from backend.monitoring.storage import DefenseStorage

logger = logging.getLogger(__name__)

_ACTION_MAP = {
    "SQL_INJECTION": "BLOCK_IP",
    "BRUTE_FORCE": "BLOCK_IP",
    "PATH_TRAVERSAL": "BLOCK_IP",
    "COMMAND_INJECTION": "BLOCK_IP",
    "PORT_SCAN": "BLOCK_IP",
    "XSS": "RATE_LIMIT",
    "BOT_SCAN": "RATE_LIMIT",
    "DDOS": "BLOCK_IP",
    "DEFAULT": "BLOCK_IP",
}


class DefenseEngine:
    """
    Execute automated defensive actions in response to detected attacks.

    Safety guarantees:
    - Whitelisted / private IPs are NEVER blocked.
    - Dry-run mode logs actions without applying them.
    - Every action is written to the database.
    """

    def __init__(self):
        self.ip_blocker = IPBlocker()
        self.rate_limiter = RateLimiter()
        self.whitelist = WhitelistManager()
        self._storage = DefenseStorage()
        self.scheduler = UnblockScheduler(self.ip_blocker, self._storage)
        self._auto_block = settings.defense.enable_auto_block
        self._dry_run = settings.defense.dry_run_mode

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute_defense(self, attack_info: Dict) -> Dict:
        """
        Execute the appropriate defense for the given *attack_info* dict.

        Returns a result dict describing what was (or would be) done.
        """
        ip = attack_info.get("ip", "")
        attack_type = attack_info.get("attack_type", "DEFAULT")
        severity = attack_info.get("severity", "MEDIUM")

        if not ip:
            return {"success": False, "reason": "No IP address provided"}

        if self.whitelist.is_whitelisted(ip):
            logger.info("Skipping defense – IP %s is whitelisted", ip)
            return {"success": True, "action": "WHITELISTED", "ip": ip}

        if not self._auto_block and not self._dry_run:
            logger.info("Auto-block disabled – logging attack only")
            return {"success": True, "action": "ALERT_ONLY", "ip": ip}

        action = _ACTION_MAP.get(attack_type, _ACTION_MAP["DEFAULT"])
        duration = settings.defense.ban_durations.get(
            attack_type,
            settings.defense.ban_durations["DEFAULT"],
        )
        unblock_at = datetime.utcnow() + timedelta(seconds=duration)

        if action == "BLOCK_IP":
            return self._block_ip(ip, attack_type, severity, duration, unblock_at)
        elif action == "RATE_LIMIT":
            return self._rate_limit(ip, attack_type, severity, duration)
        else:
            return {"success": True, "action": "ALERT_ONLY", "ip": ip}

    def execute_defense_bulk(self, detections: List[Dict]) -> List[Dict]:
        """Execute defense for each detection (highest severity first)."""
        seen_ips: set = set()
        results = []
        for det in detections:
            ip = det.get("ip", "")
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            results.append(self.execute_defense(det))
        return results

    def manual_block(self, ip: str, reason: str = "Manual block",
                     duration: int = 3600) -> Dict:
        unblock_at = datetime.utcnow() + timedelta(seconds=duration)
        return self._block_ip(ip, "MANUAL", "HIGH", duration, unblock_at,
                              performed_by="MANUAL", reason=reason)

    def manual_unblock(self, ip: str) -> Dict:
        success = self.ip_blocker.unblock_ip(ip)
        self._storage.remove_blocked_ip(ip)
        self.scheduler.cancel_unblock(ip)
        self._storage.log_action(
            action_type="UNBLOCK_IP",
            target_ip=ip,
            status="SUCCESS" if success else "FAILED",
            details="Manual unblock",
            performed_by="MANUAL",
        )
        return {"success": success, "action": "UNBLOCK_IP", "ip": ip}

    def emergency_unblock_all(self) -> Dict:
        """Unblock every IP (emergency use only)."""
        logger.warning("EMERGENCY: unblocking all IPs")
        self.ip_blocker.flush_all()
        for row in self._storage.get_blocked_ips():
            self._storage.remove_blocked_ip(row["ip"])
        return {"success": True, "action": "EMERGENCY_UNBLOCK_ALL"}

    def set_dry_run(self, enabled: bool):
        self._dry_run = enabled
        self.ip_blocker._dry_run = enabled
        logger.info("Dry-run mode: %s", enabled)

    def set_auto_block(self, enabled: bool):
        self._auto_block = enabled
        logger.info("Auto-block: %s", enabled)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _block_ip(self, ip: str, attack_type: str, severity: str,
                  duration: int, unblock_at: datetime,
                  performed_by: str = "SYSTEM",
                  reason: str = None) -> Dict:

        if self._storage.is_ip_blocked(ip):
            return {"success": True, "action": "ALREADY_BLOCKED", "ip": ip}

        success = self.ip_blocker.block_ip(ip, reason or attack_type)
        block_reason = reason or f"Automated block – {attack_type}"

        self._storage.add_blocked_ip(
            ip=ip, attack_type=attack_type, severity=severity,
            unblock_time=unblock_at, reason=block_reason,
            blocked_by=performed_by,
        )
        self._storage.log_action(
            action_type="BLOCK_IP",
            target_ip=ip,
            attack_type=attack_type,
            severity=severity,
            duration=duration,
            status="SUCCESS" if success else "FAILED",
            details=block_reason,
            performed_by=performed_by,
        )

        if success:
            self.scheduler.schedule_unblock(ip, duration)

        logger.info(
            "Defense executed: BLOCK_IP ip=%s attack=%s duration=%ds",
            ip, attack_type, duration,
        )
        return {
            "success": success,
            "action": "BLOCK_IP",
            "ip": ip,
            "attack_type": attack_type,
            "duration": duration,
            "unblock_at": unblock_at.isoformat(),
            "dry_run": self._dry_run,
        }

    def _rate_limit(self, ip: str, attack_type: str, severity: str,
                    duration: int) -> Dict:
        success = self.rate_limiter.apply_rate_limit(ip, duration)
        self._storage.log_action(
            action_type="RATE_LIMIT",
            target_ip=ip,
            attack_type=attack_type,
            severity=severity,
            duration=duration,
            status="SUCCESS" if success else "FAILED",
            performed_by="SYSTEM",
        )
        return {
            "success": success,
            "action": "RATE_LIMIT",
            "ip": ip,
            "duration": duration,
        }
