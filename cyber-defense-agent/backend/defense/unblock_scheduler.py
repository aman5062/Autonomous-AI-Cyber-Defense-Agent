"""
Scheduled auto-unblock of IPs after their ban duration expires.
"""

import logging
from datetime import datetime, timedelta

from backend.config import settings

logger = logging.getLogger(__name__)

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    _APScheduler_AVAILABLE = True
except ImportError:
    _APScheduler_AVAILABLE = False
    logger.warning("APScheduler not available – auto-unblock disabled")


class UnblockScheduler:
    """Schedule automatic IP unblocks after a configurable delay."""

    def __init__(self, ip_blocker, defense_storage):
        self._blocker = ip_blocker
        self._storage = defense_storage
        self._scheduler = None

        if _APScheduler_AVAILABLE:
            self._scheduler = BackgroundScheduler(timezone="UTC")
            self._scheduler.start()
            logger.info("UnblockScheduler started")

    def schedule_unblock(self, ip: str, duration_seconds: int):
        """Schedule *ip* to be unblocked after *duration_seconds*."""
        unblock_at = datetime.utcnow() + timedelta(seconds=duration_seconds)

        if self._scheduler:
            self._scheduler.add_job(
                func=self._do_unblock,
                trigger="date",
                run_date=unblock_at,
                args=[ip],
                id=f"unblock_{ip}_{int(unblock_at.timestamp())}",
                replace_existing=True,
                misfire_grace_time=300,
            )
            logger.info("Scheduled unblock of %s at %s", ip, unblock_at.isoformat())
        else:
            logger.info(
                "[NO-SCHEDULER] IP %s should be unblocked at %s",
                ip, unblock_at.isoformat(),
            )

    def cancel_unblock(self, ip: str):
        """Cancel any pending unblock jobs for *ip*."""
        if not self._scheduler:
            return
        for job in self._scheduler.get_jobs():
            if job.id.startswith(f"unblock_{ip}_"):
                job.remove()
                logger.info("Cancelled pending unblock for %s", ip)

    def shutdown(self):
        if self._scheduler and self._scheduler.running:
            self._scheduler.shutdown(wait=False)

    def _do_unblock(self, ip: str):
        try:
            self._blocker.unblock_ip(ip)
            self._storage.remove_blocked_ip(ip)
            self._storage.log_action(
                action_type="UNBLOCK_IP",
                target_ip=ip,
                status="SUCCESS",
                details="Auto-unblock after ban duration",
                performed_by="SCHEDULER",
            )
            logger.info("Auto-unblocked IP %s", ip)
        except Exception as exc:  # noqa: BLE001
            logger.error("Auto-unblock failed for %s: %s", ip, exc)
