import os
import requests
import logging

logger = logging.getLogger(__name__)

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")


def _get(path: str, params: dict = None) -> dict:
    try:
        r = requests.get(f"{BACKEND_URL}{path}", params=params, timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.warning(f"GET {path} failed: {e}")
        return {}


def _post(path: str, body: dict = None) -> dict:
    try:
        r = requests.post(f"{BACKEND_URL}{path}", json=body or {}, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.warning(f"POST {path} failed: {e}")
        return {}


def fetch_health() -> dict:
    return _get("/health")


def fetch_recent_attacks(limit: int = 50) -> list:
    data = _get("/api/attacks/recent", {"limit": limit})
    return data.get("attacks", [])


def fetch_blocked_ips() -> list:
    data = _get("/api/defense/blocked-ips")
    return data.get("blocked_ips", [])


def fetch_stats(days: int = 7) -> dict:
    return _get("/api/stats/attacks", {"days": days})


def fetch_latest_scan() -> dict:
    return _get("/api/scan/latest")


def block_ip(ip: str, reason: str, duration: int = 3600) -> dict:
    return _post("/api/defense/block-ip", {"ip": ip, "reason": reason, "duration": duration})


def unblock_ip(ip: str) -> dict:
    return _post("/api/defense/unblock-ip", {"ip": ip})


def emergency_unblock() -> dict:
    return _post("/api/defense/emergency-unblock")


def set_defense_mode(auto_defense: bool = None, dry_run: bool = None) -> dict:
    body = {}
    if auto_defense is not None:
        body["auto_defense"] = auto_defense
    if dry_run is not None:
        body["dry_run"] = dry_run
    return _post("/api/defense/mode", body)


def run_scan() -> dict:
    return _post("/api/scan/run")


def run_simulation(attack_type: str = "all") -> dict:
    return _post("/api/simulate", {"attack_type": attack_type})
