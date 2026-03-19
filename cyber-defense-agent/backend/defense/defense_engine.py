import logging
from datetime import datetime, timedelta
from backend.config import settings
from backend.defense.ip_blocker import IPBlocker
from backend.defense.whitelist_manager import WhitelistManager
from backend.defense.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class DefenseEngine:
    def __init__(self, storage):
        self.storage = storage
        self.blocker = IPBlocker()
        self.whitelist = WhitelistManager()
        self.rate_limiter = RateLimiter()
        self.auto_block = settings.AUTO_BLOCK_ENABLED
        self.dry_run = settings.DRY_RUN_MODE
        self.ban_durations = settings.BAN_DURATIONS
        self._scheduler = None  # injected after init to avoid circular import

    def set_scheduler(self, scheduler):
        self._scheduler = scheduler

    async def execute_defense(self, request: dict, attack_info: dict) -> dict:
        ip = request.get("ip", "")
        attack_type = attack_info.get("attack_type", "UNKNOWN")
        severity = attack_info.get("severity", "LOW")
        recommended = attack_info.get("recommended_action", "ALERT_ONLY")

        if self.whitelist.is_whitelisted(ip):
            logger.info(f"Skipping defense for whitelisted IP: {ip}")
            return {"action": "WHITELISTED", "ip": ip}

        if self.dry_run:
            logger.info(f"[DRY-RUN] Would {recommended} for {ip} ({attack_type})")
            return {"action": f"DRY_RUN_{recommended}", "ip": ip}

        action_taken = "ALERT_ONLY"

        if recommended == "BLOCK_IP" and self.auto_block:
            duration = self.ban_durations.get(attack_type, self.ban_durations.get("DEFAULT", 3600))
            success = self.blocker.block_ip(ip, reason=f"{attack_type} detected")

            if success:
                unblock_time = None
                if duration > 0:
                    unblock_time = (datetime.utcnow() + timedelta(seconds=duration)).isoformat()

                await self.storage.add_blocked_ip(
                    ip=ip,
                    attack_type=attack_type,
                    severity=severity,
                    unblock_time=unblock_time,
                    reason=f"Auto-blocked: {attack_type}",
                )
                await self.storage.save_defense_action(
                    action_type="BLOCK_IP",
                    ip=ip,
                    attack_type=attack_type,
                    severity=severity,
                    duration=duration,
                    status="SUCCESS",
                    details=attack_info.get("details", ""),
                )
                action_taken = "BLOCK_IP"

                # Schedule auto-unblock
                if duration > 0 and self._scheduler:
                    self._scheduler.schedule_unblock(ip, duration)

        elif recommended == "RATE_LIMIT":
            self.rate_limiter.check(ip)
            await self.storage.save_defense_action(
                action_type="RATE_LIMIT",
                ip=ip,
                attack_type=attack_type,
                severity=severity,
                duration=0,
                status="SUCCESS",
                details=attack_info.get("details", ""),
            )
            action_taken = "RATE_LIMIT"

        return {"action": action_taken, "ip": ip, "attack_type": attack_type}

    async def unblock_ip(self, ip: str, performed_by: str = "MANUAL") -> dict:
        success = self.blocker.unblock_ip(ip)
        await self.storage.remove_blocked_ip(ip)
        await self.storage.save_defense_action(
            action_type="UNBLOCK_IP",
            ip=ip,
            attack_type="",
            severity="",
            duration=0,
            status="SUCCESS" if success else "FAILED",
            performed_by=performed_by,
        )
        return {"success": success, "ip": ip}

    async def block_ip_manual(self, ip: str, reason: str, duration: int = 3600) -> dict:
        if self.whitelist.is_whitelisted(ip):
            return {"success": False, "message": f"{ip} is whitelisted"}

        success = self.blocker.block_ip(ip, reason=reason)
        if success:
            unblock_time = None
            if duration > 0:
                unblock_time = (datetime.utcnow() + timedelta(seconds=duration)).isoformat()
            await self.storage.add_blocked_ip(
                ip=ip,
                attack_type="MANUAL",
                severity="MANUAL",
                unblock_time=unblock_time,
                reason=reason,
                blocked_by="MANUAL",
            )
            await self.storage.save_defense_action(
                action_type="BLOCK_IP",
                ip=ip,
                attack_type="MANUAL",
                severity="MANUAL",
                duration=duration,
                status="SUCCESS",
                details=reason,
                performed_by="MANUAL",
            )
        return {"success": success, "ip": ip, "unblock_time": unblock_time if success else None}

    async def emergency_unblock_all(self) -> dict:
        blocked = await self.storage.get_blocked_ips()
        count = 0
        for entry in blocked:
            ip = entry["ip"]
            self.blocker.unblock_ip(ip)
            await self.storage.remove_blocked_ip(ip)
            count += 1
        logger.warning(f"EMERGENCY UNBLOCK: Released {count} IPs.")
        return {"unblocked": count}

    async def toggle_auto_defense(self, enabled: bool):
        self.auto_block = enabled
        await self.storage.set_config("auto_defense_enabled", str(enabled).lower())

    async def toggle_dry_run(self, enabled: bool):
        self.dry_run = enabled
        await self.storage.set_config("dry_run_mode", str(enabled).lower())
