import logging
from datetime import datetime, timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler

logger = logging.getLogger(__name__)


class UnblockScheduler:
    def __init__(self, defense_engine):
        self.defense_engine = defense_engine
        self.scheduler = AsyncIOScheduler()

    def start(self):
        self.scheduler.start()
        logger.info("Unblock scheduler started.")

    def stop(self):
        self.scheduler.shutdown(wait=False)

    def schedule_unblock(self, ip: str, duration_seconds: int):
        if duration_seconds <= 0:
            logger.info(f"IP {ip} blocked indefinitely (manual review required).")
            return

        run_at = datetime.utcnow() + timedelta(seconds=duration_seconds)
        job_id = f"unblock_{ip}"

        # Remove existing job for same IP if any
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)

        self.scheduler.add_job(
            func=self._do_unblock,
            trigger="date",
            run_date=run_at,
            args=[ip],
            id=job_id,
            misfire_grace_time=300,
        )
        logger.info(f"Scheduled unblock for {ip} at {run_at.isoformat()}")

    async def _do_unblock(self, ip: str):
        logger.info(f"Auto-unblocking IP: {ip}")
        await self.defense_engine.unblock_ip(ip, performed_by="SCHEDULER")

    async def restore_pending_unblocks(self):
        """Re-schedule any pending unblocks from DB after restart."""
        try:
            pending = await self.defense_engine.storage.get_pending_unblocks()
            now = datetime.utcnow()
            for entry in pending:
                unblock_time_str = entry.get("unblock_time")
                if not unblock_time_str:
                    continue
                try:
                    unblock_time = datetime.fromisoformat(unblock_time_str)
                    if unblock_time > now:
                        remaining = int((unblock_time - now).total_seconds())
                        self.schedule_unblock(entry["ip"], remaining)
                    else:
                        # Already expired — unblock now
                        await self._do_unblock(entry["ip"])
                except Exception as e:
                    logger.warning(f"Could not restore unblock for {entry.get('ip')}: {e}")
        except Exception as e:
            logger.error(f"restore_pending_unblocks failed: {e}")
