import asyncio
import logging
from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import JSONResponse
from backend.api.models import BlockIPRequest, UnblockIPRequest, DefenseModeRequest, SimulateRequest

logger = logging.getLogger(__name__)
router = APIRouter()

# WebSocket connection manager
_ws_clients: list = []


@router.get("/health")
async def health(request: Request):
    storage = request.app.state.storage
    ollama_ok = False
    try:
        import aiohttp
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{request.app.state.llm_analyzer.base_url}/api/tags", timeout=aiohttp.ClientTimeout(total=3)) as r:
                ollama_ok = r.status == 200
    except Exception:
        pass

    return {
        "status": "healthy",
        "services": {
            "database": "connected",
            "ollama": "ready" if ollama_ok else "unavailable",
            "defense_engine": "active" if not request.app.state.defense_engine.dry_run else "dry-run",
        },
    }


@router.get("/api/attacks/recent")
async def get_recent_attacks(request: Request, limit: int = 50):
    attacks = await request.app.state.storage.get_recent_attacks(limit=limit)
    return {"attacks": attacks, "total": len(attacks)}


@router.get("/api/defense/blocked-ips")
async def get_blocked_ips(request: Request):
    blocked = await request.app.state.storage.get_blocked_ips()
    return {"blocked_ips": blocked, "total": len(blocked)}


@router.post("/api/defense/block-ip")
async def block_ip(request: Request, body: BlockIPRequest):
    result = await request.app.state.defense_engine.block_ip_manual(
        ip=body.ip, reason=body.reason, duration=body.duration
    )
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result.get("message", "Block failed"))
    return result


@router.post("/api/defense/unblock-ip")
async def unblock_ip(request: Request, body: UnblockIPRequest):
    result = await request.app.state.defense_engine.unblock_ip(body.ip, performed_by="MANUAL")
    return result


@router.post("/api/defense/emergency-unblock")
async def emergency_unblock(request: Request):
    result = await request.app.state.defense_engine.emergency_unblock_all()
    return result


@router.post("/api/defense/mode")
async def set_defense_mode(request: Request, body: DefenseModeRequest):
    engine = request.app.state.defense_engine
    if body.auto_defense is not None:
        await engine.toggle_auto_defense(body.auto_defense)
    if body.dry_run is not None:
        await engine.toggle_dry_run(body.dry_run)
    return {
        "auto_defense": engine.auto_block,
        "dry_run": engine.dry_run,
    }


@router.get("/api/stats/attacks")
async def get_attack_stats(request: Request, days: int = 7):
    return await request.app.state.storage.get_attack_stats(days=days)


@router.get("/api/scan/latest")
async def get_latest_scan(request: Request):
    result = await request.app.state.storage.get_latest_scan()
    return result or {"message": "No scans yet"}


@router.post("/api/scan/run")
async def run_scan(request: Request):
    from backend.scanning.vulnerability_scanner import VulnerabilityScanner
    scanner = VulnerabilityScanner(storage=request.app.state.storage)
    asyncio.create_task(scanner.run_scan())
    return {"message": "Vulnerability scan started in background"}


@router.post("/api/simulate")
async def simulate_attack(request: Request, body: SimulateRequest):
    from backend.scanning.attack_simulator import AttackSimulator
    sim = AttackSimulator()
    attack_type = body.attack_type.lower()

    async def run():
        if attack_type == "all":
            return await sim.run_all()
        elif attack_type == "sql_injection":
            return await sim.simulate_sql_injection()
        elif attack_type == "xss":
            return await sim.simulate_xss()
        elif attack_type == "path_traversal":
            return await sim.simulate_path_traversal()
        elif attack_type == "brute_force":
            return await sim.simulate_brute_force()
        else:
            return {"error": f"Unknown attack type: {attack_type}"}

    asyncio.create_task(run())
    return {"message": f"Attack simulation '{attack_type}' started"}


@router.websocket("/ws/attacks")
async def ws_attacks(websocket: WebSocket):
    await websocket.accept()
    _ws_clients.append(websocket)
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        _ws_clients.remove(websocket)
    except Exception:
        if websocket in _ws_clients:
            _ws_clients.remove(websocket)


async def broadcast_attack(attack: dict):
    """Called from monitoring pipeline to push live events to dashboard."""
    dead = []
    for ws in _ws_clients:
        try:
            await ws.send_json({"type": "new_attack", "data": attack})
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.remove(ws)
