import psutil
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class MetricsCollector:
    """Collects system resource metrics."""

    def get_snapshot(self) -> dict:
        try:
            net = psutil.net_io_counters()
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "memory_used_mb": psutil.virtual_memory().used // (1024 * 1024),
                "net_bytes_sent": net.bytes_sent,
                "net_bytes_recv": net.bytes_recv,
                "net_packets_sent": net.packets_sent,
                "net_packets_recv": net.packets_recv,
            }
        except Exception as e:
            logger.error(f"Metrics collection error: {e}")
            return {}
