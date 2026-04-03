"""
System metrics collector using psutil.
"""

import logging
from datetime import datetime
from typing import Dict

logger = logging.getLogger(__name__)

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False
    logger.warning("psutil not available – system metrics will be empty")


class MetricsCollector:
    """Collect system resource metrics."""

    def get_metrics(self) -> Dict:
        if not _PSUTIL_AVAILABLE:
            return {"available": False}

        try:
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            net = psutil.net_io_counters()
            return {
                "available": True,
                "timestamp": datetime.utcnow().isoformat(),
                "cpu_percent": cpu,
                "memory_percent": mem.percent,
                "memory_used_mb": mem.used // (1024 * 1024),
                "memory_total_mb": mem.total // (1024 * 1024),
                "disk_percent": disk.percent,
                "net_bytes_sent": net.bytes_sent,
                "net_bytes_recv": net.bytes_recv,
            }
        except Exception as exc:  # noqa: BLE001
            logger.error("Metrics collection error: %s", exc)
            return {"available": False, "error": "Metrics collection failed"}
