"""
Configuration management for Autonomous AI Cyber Defense Agent
"""

import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import List

BASE_DIR = Path(__file__).parent.parent


def _load_yaml_config() -> dict:
    config_path = BASE_DIR / "config" / "settings.yaml"
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    return {}


_cfg = _load_yaml_config()


@dataclass
class DatabaseConfig:
    url: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/data/db/cyber_defense.db")
    echo: bool = False


@dataclass
class OllamaConfig:
    api_url: str = os.getenv("OLLAMA_API_URL", "http://localhost:11434")
    model: str = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
    temperature: float = 0.3
    max_tokens: int = 1000
    timeout: int = 60


@dataclass
class DetectionConfig:
    brute_force_threshold: int = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
    brute_force_window: int = int(os.getenv("BRUTE_FORCE_WINDOW", "60"))
    sql_confidence_threshold: float = 0.7
    enable_anomaly_detection: bool = False


@dataclass
class DefenseConfig:
    enable_auto_block: bool = os.getenv("ENABLE_AUTO_BLOCK", "true").lower() == "true"
    dry_run_mode: bool = os.getenv("DRY_RUN_MODE", "false").lower() == "true"
    whitelist: List[str] = field(default_factory=lambda: (
        ["127.0.0.1", "::1", "localhost"] +
        [ip for ip in os.getenv("WHITELIST_IPS", "").split(",") if ip.strip()]
    ))
    ban_durations: dict = field(default_factory=lambda: {
        "SQL_INJECTION": 86400,
        "BRUTE_FORCE": 3600,
        "PATH_TRAVERSAL": 86400,
        "XSS": 21600,
        "COMMAND_INJECTION": 86400,
        "PORT_SCAN": 172800,
        "DDOS": 86400,
        "DEFAULT": 3600,
    })


@dataclass
class MonitoringConfig:
    nginx_log_path: str = os.getenv(
        "NGINX_LOG_PATH",
        str(BASE_DIR / "data" / "logs" / "access.log")
    )
    poll_interval: float = 0.5
    metrics_interval: int = 30


@dataclass
class ServerConfig:
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8000"))
    log_level: str = os.getenv("LOG_LEVEL", "info")
    cors_origins: List[str] = field(default_factory=lambda: ["*"])


@dataclass
class AppConfig:
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    defense: DefenseConfig = field(default_factory=DefenseConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"


# Singleton config
settings = AppConfig()
