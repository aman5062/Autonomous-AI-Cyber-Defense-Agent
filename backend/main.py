"""
FastAPI application entry point for the Autonomous AI Cyber Defense Agent.
"""

import asyncio
import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.monitoring.log_collector import LogCollector, SimulatedLogCollector
from backend.monitoring.log_parser import NginxLogParser
from backend.monitoring.storage import LogStorage, DefenseStorage, init_db
from backend.detection.detection_engine import AttackDetectionEngine
from backend.defense.defense_engine import DefenseEngine
from backend.analysis.llm_analyzer import LLMAnalyzer
from backend.api.routes import router, init_routes, broadcast_attack
from backend.analysis.email_reporter import EmailReporter
from backend.monitoring.wifi_monitor import WiFiMonitor

logging.basicConfig(
    level=getattr(logging, settings.server.log_level.upper(), logging.INFO),
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

_log_storage: LogStorage = None
_defense_storage: DefenseStorage = None
_detection_engine: AttackDetectionEngine = None
_defense_engine: DefenseEngine = None
_analyzer: LLMAnalyzer = None
_email_reporter: EmailReporter = None
_wifi_monitor: WiFiMonitor = None
_monitor_task: asyncio.Task = None


async def _monitor_loop():
    parser = NginxLogParser()
    use_simulated = not (
        settings.monitoring.nginx_log_path and
        __import__("pathlib").Path(settings.monitoring.nginx_log_path).exists()
    )
    if use_simulated:
        logger.info("Real NGINX log not found – using simulated traffic for demo")
        collector = SimulatedLogCollector(interval=3.0)
    else:
        logger.info("Monitoring NGINX log: %s", settings.monitoring.nginx_log_path)
        collector = LogCollector()

    async for line in collector.tail_logs_async():
        try:
            await _process_log_line(parser, line)
        except Exception as exc:
            logger.error("Monitor loop error: %s", exc)


async def _process_log_line(parser: NginxLogParser, line: str):
    parsed = parser.parse(line)
    if not parsed:
        return

    request_id = _log_storage.save_request(parsed)
    detections = await _detection_engine.analyze_request_async(parsed)
    if not detections:
        return

    top = detections[0]
    attack_type = top.get("attack_type")
    severity = top.get("severity")

    _log_storage.mark_attack(request_id, attack_type, severity)
    defense_result = _defense_engine.execute_defense(top)
    blocked = defense_result.get("action") == "BLOCK_IP"

    if blocked:
        _log_storage.mark_attack(request_id, attack_type, severity, blocked=True)

    asyncio.create_task(_run_llm_analysis(request_id, top, parsed))
    asyncio.create_task(_run_email_report(top, parsed))

    attack_event = {
        "id": request_id,
        "timestamp": parsed.get("timestamp"),
        "ip": parsed.get("ip"),
        "method": parsed.get("method"),
        "path": parsed.get("path"),
        "status": parsed.get("status"),
        "user_agent": parsed.get("user_agent"),
        "attack_type": attack_type,
        "severity": severity,
        "blocked": blocked,
        "defense_action": defense_result.get("action"),
    }
    await broadcast_attack(attack_event)
    logger.info("Attack processed: %s", attack_event)


async def _run_llm_analysis(request_id: int, attack_data: dict, request_data: dict):
    try:
        loop = asyncio.get_event_loop()
        analysis = await loop.run_in_executor(
            None, _analyzer.analyze_attack, attack_data, request_data,
        )
        _defense_storage.save_ai_analysis(request_id, attack_data.get("attack_type"), analysis)
    except Exception as exc:
        logger.warning("LLM analysis failed: %s", exc)


async def _run_email_report(attack_data: dict, request_data: dict):
    """Send email report asynchronously after attack detection."""
    try:
        loop = asyncio.get_event_loop()
        analysis = await loop.run_in_executor(
            None, _analyzer.analyze_attack, attack_data, request_data,
        )
        await loop.run_in_executor(
            None, _email_reporter.send_attack_report, attack_data, request_data, analysis,
        )
    except Exception as exc:
        logger.warning("Email report failed: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _log_storage, _defense_storage, _detection_engine
    global _defense_engine, _analyzer, _email_reporter, _wifi_monitor, _monitor_task

    logger.info("Starting Autonomous AI Cyber Defense Agent...")
    init_db()

    _log_storage = LogStorage()
    _defense_storage = DefenseStorage()
    _detection_engine = AttackDetectionEngine()
    _defense_engine = DefenseEngine()
    _analyzer = LLMAnalyzer()
    _email_reporter = EmailReporter()
    _wifi_monitor = WiFiMonitor()
    _wifi_monitor.start()

    init_routes(_log_storage, _defense_storage, _defense_engine, _analyzer,
                _email_reporter, _wifi_monitor)
    _monitor_task = asyncio.create_task(_monitor_loop())

    logger.info("Cyber Defense Agent running – dashboard at :8501, API at :8000")
    yield

    logger.info("Shutting down...")
    if _monitor_task:
        _monitor_task.cancel()
        try:
            await _monitor_task
        except asyncio.CancelledError:
            pass
    if _wifi_monitor:
        _wifi_monitor.stop()
    if _defense_engine:
        _defense_engine.scheduler.shutdown()


app = FastAPI(
    title="Autonomous AI Cyber Defense Agent",
    description="Real-time threat detection, automated defense, and LLM-powered analysis",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.server.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.server.host,
        port=settings.server.port,
        log_level=settings.server.log_level,
        reload=settings.debug,
    )
