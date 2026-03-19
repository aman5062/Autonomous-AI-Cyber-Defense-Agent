import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.api.routes import router
from backend.monitoring.storage import LogStorage
from backend.monitoring.log_collector import LogCollector
from backend.detection.detection_engine import AttackDetectionEngine
from backend.defense.defense_engine import DefenseEngine
from backend.analysis.llm_analyzer import LLMAnalyzer
from backend.defense.unblock_scheduler import UnblockScheduler

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Global service instances
storage: LogStorage = None
detection_engine: AttackDetectionEngine = None
defense_engine: DefenseEngine = None
llm_analyzer: LLMAnalyzer = None
unblock_scheduler: UnblockScheduler = None
log_collector: LogCollector = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global storage, detection_engine, defense_engine, llm_analyzer, unblock_scheduler, log_collector

    logger.info("Starting AI Cyber Defense Agent...")

    # Ensure data directories exist
    os.makedirs("/app/data/db", exist_ok=True)
    os.makedirs("/app/data/logs", exist_ok=True)
    os.makedirs("/app/data/models", exist_ok=True)

    # Initialize services
    storage = LogStorage(settings.DB_PATH)
    await storage.initialize()

    detection_engine = AttackDetectionEngine()
    defense_engine = DefenseEngine(storage)
    llm_analyzer = LLMAnalyzer()
    unblock_scheduler = UnblockScheduler(defense_engine)
    unblock_scheduler.start()
    defense_engine.set_scheduler(unblock_scheduler)

    # Restore pending unblocks from DB
    await unblock_scheduler.restore_pending_unblocks()

    # Start log monitoring in background
    log_collector = LogCollector(settings.NGINX_LOG_PATH)
    asyncio.create_task(start_log_monitoring())

    # Optionally fetch CVE data
    if settings.NVD_FETCH_ON_STARTUP:
        asyncio.create_task(fetch_threat_intel())

    # Store references in app state
    app.state.storage = storage
    app.state.detection_engine = detection_engine
    app.state.defense_engine = defense_engine
    app.state.llm_analyzer = llm_analyzer
    app.state.unblock_scheduler = unblock_scheduler

    logger.info("All services initialized. System is ACTIVE.")
    yield

    # Shutdown
    logger.info("Shutting down...")
    unblock_scheduler.stop()


async def start_log_monitoring():
    """Background task: tail NGINX logs and run detection pipeline."""
    logger.info(f"Starting log monitoring on {settings.NGINX_LOG_PATH}")
    async for parsed_request in log_collector.tail_logs_async():
        try:
            # Save request
            request_id = await storage.save_request(parsed_request)
            parsed_request["id"] = request_id

            # Run detection
            detections = detection_engine.analyze_request(parsed_request)

            if detections:
                highest = max(detections, key=lambda d: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(d["severity"], 0))
                await storage.mark_suspicious(request_id, highest["attack_type"], highest["severity"])

                # Execute defense
                defense_result = await defense_engine.execute_defense(parsed_request, highest)

                # Async LLM analysis (non-blocking)
                asyncio.create_task(
                    run_llm_analysis(request_id, parsed_request, highest)
                )

                logger.warning(
                    f"ATTACK DETECTED: {highest['attack_type']} from {parsed_request.get('ip')} "
                    f"| Severity: {highest['severity']} | Action: {defense_result.get('action')}"
                )
        except Exception as e:
            logger.error(f"Error in monitoring pipeline: {e}")


async def run_llm_analysis(request_id: int, request_data: dict, attack_info: dict):
    """Run LLM analysis and store result."""
    try:
        analysis = await llm_analyzer.analyze_attack(attack_info, request_data)
        await storage.save_analysis(request_id, attack_info["attack_type"], analysis)
    except Exception as e:
        logger.error(f"LLM analysis failed for request {request_id}: {e}")


async def fetch_threat_intel():
    """Background task: fetch CVE data into Qdrant."""
    try:
        from backend.intelligence.cve_fetcher import CVEFetcher
        fetcher = CVEFetcher()
        await fetcher.fetch_and_store()
        logger.info("Threat intelligence loaded into Qdrant.")
    except Exception as e:
        logger.warning(f"Threat intel fetch failed (non-critical): {e}")


app = FastAPI(
    title="AI Cyber Defense Agent",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
