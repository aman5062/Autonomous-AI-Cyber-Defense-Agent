import os
import yaml
from pathlib import Path

CONFIG_PATH = Path(os.getenv("CONFIG_PATH", "/app/config/settings.yaml"))


def load_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f)
    return {}


_cfg = load_config()


class Settings:
    # App
    APP_NAME: str = _cfg.get("app", {}).get("name", "AI Cyber Defense Agent")
    DEBUG: bool = _cfg.get("app", {}).get("debug", False)
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", _cfg.get("app", {}).get("log_level", "INFO"))

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", _cfg.get("database", {}).get("url", "sqlite:////app/data/db/cyber_defense.db")
    )

    # NGINX logs
    NGINX_LOG_PATH: str = _cfg.get("nginx", {}).get("log_path", "/var/log/nginx/access.log")

    # Ollama
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", _cfg.get("ollama", {}).get("base_url", "http://ollama:11434"))
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", _cfg.get("ollama", {}).get("model", "llama3.2:3b"))
    OLLAMA_TEMPERATURE: float = _cfg.get("ollama", {}).get("temperature", 0.3)
    OLLAMA_MAX_TOKENS: int = _cfg.get("ollama", {}).get("max_tokens", 1000)
    OLLAMA_TIMEOUT: int = _cfg.get("ollama", {}).get("timeout", 120)

    # Qdrant
    QDRANT_HOST: str = os.getenv("QDRANT_HOST", _cfg.get("qdrant", {}).get("host", "qdrant"))
    QDRANT_PORT: int = _cfg.get("qdrant", {}).get("port", 6333)
    QDRANT_COLLECTION: str = _cfg.get("qdrant", {}).get("collection_name", "threat_intelligence")

    # Defense
    AUTO_BLOCK_ENABLED: bool = _cfg.get("defense", {}).get("auto_block_enabled", True)
    DRY_RUN_MODE: bool = os.getenv("DRY_RUN_MODE", "false").lower() == "true"
    WHITELIST: list = _cfg.get("defense", {}).get("whitelist", ["127.0.0.1", "::1"])
    BAN_DURATIONS: dict = _cfg.get("defense", {}).get("ban_durations", {
        "SQL_INJECTION": 86400,
        "BRUTE_FORCE": 3600,
        "PATH_TRAVERSAL": 86400,
        "XSS": 21600,
        "DEFAULT": 3600,
    })

    # Detection
    BRUTE_FORCE_THRESHOLD: int = _cfg.get("detection", {}).get("brute_force_threshold", 5)
    BRUTE_FORCE_WINDOW: int = _cfg.get("detection", {}).get("brute_force_window", 60)
    DDOS_THRESHOLD: int = _cfg.get("detection", {}).get("ddos_threshold", 100)
    DDOS_WINDOW: int = _cfg.get("detection", {}).get("ddos_window", 10)

    # Scanning
    SCAN_TARGET_HOST: str = os.getenv("SCAN_TARGET", _cfg.get("scanning", {}).get("target_host", "testapp"))
    SCAN_TARGET_PORT: int = _cfg.get("scanning", {}).get("target_port", 5000)

    # NVD
    NVD_API_URL: str = _cfg.get("nvd", {}).get("api_url", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", _cfg.get("nvd", {}).get("api_key", ""))
    NVD_FETCH_ON_STARTUP: bool = _cfg.get("nvd", {}).get("fetch_on_startup", True)

    # Attack patterns file
    PATTERNS_PATH: str = os.getenv("PATTERNS_PATH", "/app/config/attack_patterns.json")
    WHITELIST_PATH: str = os.getenv("WHITELIST_PATH", "/app/config/whitelist.txt")

    # Data paths
    DATA_DIR: str = "/app/data"
    DB_PATH: str = "/app/data/db/cyber_defense.db"
    MODELS_DIR: str = "/app/data/models"
    LOGS_DIR: str = "/app/data/logs"


settings = Settings()
