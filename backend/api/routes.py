"""
FastAPI route definitions for the Cyber Defense Agent backend.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from backend.api.models import (
    AttackResponse,
    BlockedIPResponse,
    BlockIPRequest,
    DefenseModeRequest,
    HealthResponse,
    StatsResponse,
    UnblockIPRequest,
    WhitelistRequest,
)
from backend.monitoring.storage import LogStorage, DefenseStorage
from backend.monitoring.metrics_collector import MetricsCollector

logger = logging.getLogger(__name__)

router = APIRouter()

# These are injected from main.py
_log_storage: LogStorage = None
_defense_storage: DefenseStorage = None
_defense_engine = None
_analyzer = None
_metrics_collector = MetricsCollector()

# WebSocket connection manager
_ws_connections: List[WebSocket] = []


def init_routes(log_storage, defense_storage, defense_engine, analyzer):
    global _log_storage, _defense_storage, _defense_engine, _analyzer
    _log_storage = log_storage
    _defense_storage = defense_storage
    _defense_engine = defense_engine
    _analyzer = analyzer


# ------------------------------------------------------------------
# Health
# ------------------------------------------------------------------

@router.get("/health", response_model=HealthResponse, tags=["health"])
async def health_check():
    ollama_status = "unknown"
    if _analyzer:
        health = _analyzer.check_ollama_health()
        ollama_status = "ready" if health.get("available") else "unavailable"

    db_status = "connected"
    try:
        if _log_storage:
            _log_storage.get_recent_attacks(limit=1)
    except Exception:
        db_status = "error"

    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "services": {
            "database": db_status,
            "ollama": ollama_status,
            "defense_engine": "active" if _defense_engine else "unavailable",
        },
        "defense_mode": {
            "auto_block": _defense_engine._auto_block if _defense_engine else False,
            "dry_run": _defense_engine._dry_run if _defense_engine else True,
        },
    }


# ------------------------------------------------------------------
# Attacks
# ------------------------------------------------------------------

@router.get("/api/attacks/recent", tags=["attacks"])
async def get_recent_attacks(limit: int = Query(default=20, ge=1, le=200)):
    if not _log_storage:
        raise HTTPException(503, "Storage not initialised")
    attacks = _log_storage.get_recent_attacks(limit=limit)
    return {"attacks": attacks, "total": len(attacks)}


@router.get("/api/stats/attacks", response_model=StatsResponse, tags=["stats"])
async def get_attack_stats(days: int = Query(default=7, ge=1, le=90)):
    if not _log_storage:
        raise HTTPException(503, "Storage not initialised")
    return _log_storage.get_attack_stats(days=days)


# ------------------------------------------------------------------
# Defense
# ------------------------------------------------------------------

@router.get("/api/defense/blocked-ips", tags=["defense"])
async def get_blocked_ips():
    if not _defense_storage:
        raise HTTPException(503, "Storage not initialised")
    ips = _defense_storage.get_blocked_ips()
    return {"blocked_ips": ips, "total": len(ips)}


@router.post("/api/defense/block-ip", tags=["defense"])
async def block_ip(req: BlockIPRequest):
    if not _defense_engine:
        raise HTTPException(503, "Defense engine not initialised")
    result = _defense_engine.manual_block(req.ip, req.reason, req.duration)
    if not result["success"]:
        raise HTTPException(500, f"Block failed: {result}")
    return {
        "success": True,
        "message": f"IP {req.ip} blocked successfully",
        "unblock_time": result.get("unblock_at"),
    }


@router.post("/api/defense/unblock-ip", tags=["defense"])
async def unblock_ip(req: UnblockIPRequest):
    if not _defense_engine:
        raise HTTPException(503, "Defense engine not initialised")
    result = _defense_engine.manual_unblock(req.ip)
    return {
        "success": result["success"],
        "message": f"IP {req.ip} unblocked",
    }


@router.post("/api/defense/emergency-unblock", tags=["defense"])
async def emergency_unblock():
    if not _defense_engine:
        raise HTTPException(503, "Defense engine not initialised")
    result = _defense_engine.emergency_unblock_all()
    return result


@router.post("/api/defense/mode", tags=["defense"])
async def set_defense_mode(req: DefenseModeRequest):
    if not _defense_engine:
        raise HTTPException(503, "Defense engine not initialised")
    if req.auto_block is not None:
        _defense_engine.set_auto_block(req.auto_block)
    if req.dry_run is not None:
        _defense_engine.set_dry_run(req.dry_run)
    return {
        "auto_block": _defense_engine._auto_block,
        "dry_run": _defense_engine._dry_run,
    }


# ------------------------------------------------------------------
# Whitelist
# ------------------------------------------------------------------

@router.get("/api/whitelist", tags=["whitelist"])
async def get_whitelist():
    if not _defense_engine:
        raise HTTPException(503, "Defense engine not initialised")
    return {"whitelist": _defense_engine.whitelist.list_all()}


@router.post("/api/whitelist/add", tags=["whitelist"])
async def add_to_whitelist(req: WhitelistRequest):
    if not _defense_engine:
        raise HTTPException(503, "Defense engine not initialised")
    _defense_engine.whitelist.add(req.ip, req.reason)
    return {"success": True, "message": f"IP {req.ip} added to whitelist"}


@router.post("/api/whitelist/remove", tags=["whitelist"])
async def remove_from_whitelist(req: WhitelistRequest):
    if not _defense_engine:
        raise HTTPException(503, "Defense engine not initialised")
    _defense_engine.whitelist.remove(req.ip)
    return {"success": True, "message": f"IP {req.ip} removed from whitelist"}


# ------------------------------------------------------------------
# Metrics
# ------------------------------------------------------------------

@router.get("/api/metrics/system", tags=["metrics"])
async def system_metrics():
    return _metrics_collector.get_metrics()


# ------------------------------------------------------------------
# LLM / Analysis
# ------------------------------------------------------------------

@router.post("/api/analysis/analyze", tags=["analysis"])
async def analyze_attack(attack_data: Dict[str, Any], request_data: Dict[str, Any] = None):
    if not _analyzer:
        raise HTTPException(503, "LLM analyzer not initialised")
    result = _analyzer.analyze_attack(attack_data, request_data or {})
    return result


@router.get("/api/analysis/ollama-health", tags=["analysis"])
async def ollama_health():
    if not _analyzer:
        raise HTTPException(503, "LLM analyzer not initialised")
    return _analyzer.check_ollama_health()


# ------------------------------------------------------------------
# WebSocket live feed
# ------------------------------------------------------------------

@router.websocket("/ws/attacks")
async def websocket_attacks(websocket: WebSocket):
    await websocket.accept()
    _ws_connections.append(websocket)
    try:
        while True:
            # Keep-alive ping every 30 s
            await asyncio.sleep(30)
            await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        _ws_connections.remove(websocket)
    except Exception:
        if websocket in _ws_connections:
            _ws_connections.remove(websocket)


async def broadcast_attack(attack: Dict):
    """Broadcast a new attack event to all connected WebSocket clients."""
    dead = []
    for ws in list(_ws_connections):
        try:
            await ws.send_json({"type": "new_attack", "data": attack})
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_connections.remove(ws)
