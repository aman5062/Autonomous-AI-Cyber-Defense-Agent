"""
Backend API client for the Streamlit dashboard.
"""

import logging
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

import os
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")

_TIMEOUT = 8


def _get(path: str, params: dict = None) -> Optional[dict]:
    try:
        r = requests.get(f"{BACKEND_URL}{path}", params=params, timeout=_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        logger.warning("Backend not reachable at %s", BACKEND_URL)
        return None
    except Exception as exc:
        logger.warning("GET %s failed: %s", path, exc)
        return None


def _post(path: str, payload: dict = None) -> Optional[dict]:
    try:
        r = requests.post(f"{BACKEND_URL}{path}", json=payload, timeout=_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        logger.warning("POST %s failed: %s", path, exc)
        return None


# ------------------------------------------------------------------
# Public helpers called by dashboard components
# ------------------------------------------------------------------

def fetch_health() -> Optional[Dict]:
    return _get("/health")


def fetch_recent_attacks(limit: int = 30) -> List[Dict]:
    data = _get("/api/attacks/recent", params={"limit": limit})
    return (data or {}).get("attacks", [])


def fetch_blocked_ips() -> List[Dict]:
    data = _get("/api/defense/blocked-ips")
    return (data or {}).get("blocked_ips", [])


def fetch_attack_stats(days: int = 7) -> Optional[Dict]:
    return _get("/api/stats/attacks", params={"days": days})


def fetch_system_metrics() -> Optional[Dict]:
    return _get("/api/metrics/system")


def fetch_whitelist() -> List[str]:
    data = _get("/api/whitelist")
    return (data or {}).get("whitelist", [])


def block_ip(ip: str, reason: str = "Manual block", duration: int = 3600) -> bool:
    result = _post("/api/defense/block-ip", {"ip": ip, "reason": reason, "duration": duration})
    return bool(result and result.get("success"))


def unblock_ip(ip: str) -> bool:
    result = _post("/api/defense/unblock-ip", {"ip": ip})
    return bool(result and result.get("success"))


def emergency_unblock_all() -> bool:
    result = _post("/api/defense/emergency-unblock")
    return bool(result and result.get("success"))


def set_defense_mode(auto_block: Optional[bool] = None,
                     dry_run: Optional[bool] = None) -> Optional[Dict]:
    payload = {}
    if auto_block is not None:
        payload["auto_block"] = auto_block
    if dry_run is not None:
        payload["dry_run"] = dry_run
    return _post("/api/defense/mode", payload)


def add_to_whitelist(ip: str, reason: str = "") -> bool:
    result = _post("/api/whitelist/add", {"ip": ip, "reason": reason})
    return bool(result and result.get("success"))


def fetch_ollama_health() -> Optional[Dict]:
    return _get("/api/analysis/ollama-health")
