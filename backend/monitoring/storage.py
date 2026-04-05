"""
SQLite storage for log entries, attack records, defense actions, and blocked IPs.
"""

import json
import sqlite3
import logging
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from backend.config import settings

logger = logging.getLogger(__name__)

# Handle both sqlite:/// (relative) and sqlite://// (absolute) URL formats
_db_url = settings.database.url
if _db_url.startswith("sqlite:////"):
    DB_PATH = Path(_db_url[len("sqlite:///"):])   # keeps leading /
elif _db_url.startswith("sqlite:///"):
    DB_PATH = Path(_db_url[len("sqlite:///"):])
else:
    DB_PATH = Path("/app/data/db/cyber_defense.db")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    ip TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL,
    size INTEGER,
    user_agent TEXT,
    referrer TEXT,
    is_suspicious INTEGER DEFAULT 0,
    attack_type TEXT,
    severity TEXT,
    blocked INTEGER DEFAULT 0,
    raw_log TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ip ON requests(ip);
CREATE INDEX IF NOT EXISTS idx_timestamp ON requests(timestamp);
CREATE INDEX IF NOT EXISTS idx_attack_type ON requests(attack_type);
CREATE INDEX IF NOT EXISTS idx_blocked ON requests(blocked);

CREATE TABLE IF NOT EXISTS defense_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    action_type TEXT NOT NULL,
    target_ip TEXT NOT NULL,
    attack_type TEXT,
    severity TEXT,
    duration INTEGER,
    status TEXT,
    details TEXT,
    performed_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_defense_ip ON defense_actions(target_ip);
CREATE INDEX IF NOT EXISTS idx_defense_timestamp ON defense_actions(timestamp);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    attack_type TEXT,
    severity TEXT,
    block_time DATETIME NOT NULL,
    unblock_time DATETIME,
    status TEXT DEFAULT 'ACTIVE',
    reason TEXT,
    blocked_by TEXT DEFAULT 'SYSTEM'
);

CREATE INDEX IF NOT EXISTS idx_blocked_status ON blocked_ips(status);

CREATE TABLE IF NOT EXISTS ai_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER,
    attack_type TEXT,
    analysis_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    explanation TEXT,
    impact TEXT,
    mitigation TEXT,
    code_fix TEXT,
    references_list TEXT,
    FOREIGN KEY (request_id) REFERENCES requests(id)
);

CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    reason TEXT,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    added_by TEXT DEFAULT 'SYSTEM'
);

CREATE TABLE IF NOT EXISTS app_config (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    target TEXT,
    open_ports TEXT,
    vulnerabilities TEXT,
    raw TEXT
);

INSERT OR IGNORE INTO app_config (key, value) VALUES
    ('auto_defense_enabled', 'true'),
    ('dry_run_mode', 'false'),
    ('brute_force_threshold', '5'),
    ('brute_force_window', '60');
"""


@contextmanager
def get_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Initialize database schema."""
    with get_connection() as conn:
        conn.executescript(SCHEMA_SQL)
    logger.info("Database initialized at %s", DB_PATH)


class LogStorage:
    """Persist parsed request logs and attack records."""

    def save_request(self, parsed_log: Dict) -> int:
        sql = """
            INSERT INTO requests
                (timestamp, ip, method, path, status, size,
                 user_agent, referrer, raw_log)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with get_connection() as conn:
            cur = conn.execute(sql, (
                parsed_log.get("timestamp"),
                parsed_log.get("ip"),
                parsed_log.get("method", ""),
                parsed_log.get("path", ""),
                parsed_log.get("status", 0),
                parsed_log.get("size"),
                parsed_log.get("user_agent"),
                parsed_log.get("referrer"),
                parsed_log.get("raw_log"),
            ))
            return cur.lastrowid

    def mark_attack(self, request_id: int, attack_type: str,
                    severity: str, blocked: bool = False):
        sql = """
            UPDATE requests
            SET is_suspicious = 1,
                attack_type = ?,
                severity = ?,
                blocked = ?
            WHERE id = ?
        """
        with get_connection() as conn:
            conn.execute(sql, (attack_type, severity, int(blocked), request_id))

    def get_recent_attacks(self, limit: int = 50) -> List[Dict]:
        sql = """
            SELECT r.*, a.explanation, a.impact, a.mitigation, a.code_fix, a.references_list
            FROM requests r
            LEFT JOIN ai_analysis a ON a.request_id = r.id
            WHERE r.is_suspicious = 1
            ORDER BY r.created_at DESC
            LIMIT ?
        """
        with get_connection() as conn:
            rows = conn.execute(sql, (limit,)).fetchall()
        return [_row_to_dict(r) for r in rows]

    def get_requests_by_ip(self, ip: str, hours: int = 24) -> List[Dict]:
        sql = """
            SELECT * FROM requests
            WHERE ip = ?
              AND created_at >= datetime('now', ?)
            ORDER BY created_at DESC
        """
        with get_connection() as conn:
            rows = conn.execute(sql, (ip, f"-{hours} hours")).fetchall()
        return [_row_to_dict(r) for r in rows]

    def get_attack_stats(self, days: int = 7) -> Dict:
        with get_connection() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM requests WHERE is_suspicious=1 "
                "AND created_at >= datetime('now', ?)", (f"-{days} days",)
            ).fetchone()[0]

            by_type_rows = conn.execute(
                "SELECT attack_type, COUNT(*) as cnt FROM requests "
                "WHERE is_suspicious=1 AND created_at >= datetime('now', ?) "
                "GROUP BY attack_type", (f"-{days} days",)
            ).fetchall()

            by_sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM requests "
                "WHERE is_suspicious=1 AND created_at >= datetime('now', ?) "
                "GROUP BY severity", (f"-{days} days",)
            ).fetchall()

            blocked = conn.execute(
                "SELECT COUNT(*) FROM requests WHERE is_suspicious=1 AND blocked=1 "
                "AND created_at >= datetime('now', ?)", (f"-{days} days",)
            ).fetchone()[0]

            timeline_rows = conn.execute(
                "SELECT date(created_at) as date, COUNT(*) as cnt FROM requests "
                "WHERE is_suspicious=1 AND created_at >= datetime('now', ?) "
                "GROUP BY date(created_at) ORDER BY date", (f"-{days} days",)
            ).fetchall()

        return {
            "total_attacks": total,
            "by_type": {r["attack_type"]: r["cnt"] for r in by_type_rows if r["attack_type"]},
            "by_severity": {r["severity"]: r["cnt"] for r in by_sev_rows if r["severity"]},
            "blocked_count": blocked,
            "timeline": [{"date": r["date"], "count": r["cnt"]} for r in timeline_rows],
        }


class DefenseStorage:
    """Persist defense actions and blocked IP records."""

    def log_action(self, action_type: str, target_ip: str,
                   attack_type: str = None, severity: str = None,
                   duration: int = None, status: str = "SUCCESS",
                   details: str = None, performed_by: str = "SYSTEM"):
        sql = """
            INSERT INTO defense_actions
                (action_type, target_ip, attack_type, severity, duration,
                 status, details, performed_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        with get_connection() as conn:
            conn.execute(sql, (
                action_type, target_ip, attack_type, severity,
                duration, status, details, performed_by,
            ))

    def add_blocked_ip(self, ip: str, attack_type: str, severity: str,
                       unblock_time: datetime, reason: str = None,
                       blocked_by: str = "SYSTEM"):
        sql = """
            INSERT OR REPLACE INTO blocked_ips
                (ip, attack_type, severity, block_time, unblock_time,
                 status, reason, blocked_by)
            VALUES (?, ?, ?, datetime('now'), ?, 'ACTIVE', ?, ?)
        """
        with get_connection() as conn:
            conn.execute(sql, (ip, attack_type, severity,
                               unblock_time.isoformat() if unblock_time else None,
                               reason, blocked_by))

    def remove_blocked_ip(self, ip: str):
        sql = "UPDATE blocked_ips SET status='UNBLOCKED' WHERE ip=?"
        with get_connection() as conn:
            conn.execute(sql, (ip,))

    def get_blocked_ips(self) -> List[Dict]:
        sql = "SELECT * FROM blocked_ips WHERE status='ACTIVE' ORDER BY block_time DESC"
        with get_connection() as conn:
            rows = conn.execute(sql).fetchall()
        return [_row_to_dict(r) for r in rows]

    def is_ip_blocked(self, ip: str) -> bool:
        sql = "SELECT 1 FROM blocked_ips WHERE ip=? AND status='ACTIVE'"
        with get_connection() as conn:
            return conn.execute(sql, (ip,)).fetchone() is not None

    def save_ai_analysis(self, request_id: Optional[int], attack_type: str,
                         analysis: Dict):
        sql = """
            INSERT INTO ai_analysis
                (request_id, attack_type, explanation, impact, mitigation,
                 code_fix, references_list)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        with get_connection() as conn:
            conn.execute(sql, (
                request_id,
                attack_type,
                analysis.get("explanation"),
                analysis.get("impact"),
                json.dumps(analysis.get("mitigation", [])),
                json.dumps(analysis.get("code_fix", {})),
                json.dumps(analysis.get("references", [])),
            ))

    def get_config(self, key: str) -> Optional[str]:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT value FROM app_config WHERE key=?", (key,)
            ).fetchone()
        return row["value"] if row else None

    def set_config(self, key: str, value: str):
        with get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO app_config (key, value) VALUES (?, ?)",
                (key, value),
            )

    async def save_scan_result(self, target: str, open_ports: list,
                                vulnerabilities: list, raw: str = ""):
        sql = """
            INSERT INTO scan_results (target, open_ports, vulnerabilities, raw)
            VALUES (?, ?, ?, ?)
        """
        with get_connection() as conn:
            conn.execute(sql, (
                target,
                json.dumps(open_ports),
                json.dumps(vulnerabilities),
                raw,
            ))

    def get_scan_results(self, limit: int = 10) -> list:
        sql = "SELECT * FROM scan_results ORDER BY scan_time DESC LIMIT ?"
        with get_connection() as conn:
            rows = conn.execute(sql, (limit,)).fetchall()
        return [_row_to_dict(r) for r in rows]


def _row_to_dict(row: sqlite3.Row) -> Dict:
    d = dict(row)
    for field in ("mitigation", "code_fix", "references_list"):
        if d.get(field) and isinstance(d[field], str):
            try:
                d[field] = json.loads(d[field])
            except (json.JSONDecodeError, TypeError):
                pass
    return d
