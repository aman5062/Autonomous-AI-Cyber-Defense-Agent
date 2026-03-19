import aiosqlite
import json
import logging
from datetime import datetime
from typing import List, Optional

logger = logging.getLogger(__name__)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    ip TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL,
    size INTEGER DEFAULT 0,
    user_agent TEXT,
    referrer TEXT,
    is_suspicious INTEGER DEFAULT 0,
    attack_type TEXT,
    severity TEXT,
    blocked INTEGER DEFAULT 0,
    raw_log TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ip ON requests(ip);
CREATE INDEX IF NOT EXISTS idx_timestamp ON requests(timestamp);
CREATE INDEX IF NOT EXISTS idx_attack_type ON requests(attack_type);
CREATE INDEX IF NOT EXISTS idx_blocked ON requests(blocked);

CREATE TABLE IF NOT EXISTS defense_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT DEFAULT (datetime('now')),
    action_type TEXT NOT NULL,
    target_ip TEXT NOT NULL,
    attack_type TEXT,
    severity TEXT,
    duration INTEGER,
    status TEXT,
    details TEXT,
    performed_by TEXT DEFAULT 'SYSTEM'
);
CREATE INDEX IF NOT EXISTS idx_defense_ip ON defense_actions(target_ip);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    attack_type TEXT,
    severity TEXT,
    block_time TEXT NOT NULL,
    unblock_time TEXT,
    status TEXT DEFAULT 'ACTIVE',
    reason TEXT,
    blocked_by TEXT DEFAULT 'SYSTEM'
);
CREATE INDEX IF NOT EXISTS idx_blocked_status ON blocked_ips(status);

CREATE TABLE IF NOT EXISTS ai_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER,
    attack_type TEXT,
    analysis_time TEXT DEFAULT (datetime('now')),
    explanation TEXT,
    impact TEXT,
    mitigation TEXT,
    code_fix TEXT,
    refs TEXT,
    FOREIGN KEY (request_id) REFERENCES requests(id)
);

CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    reason TEXT,
    added_at TEXT DEFAULT (datetime('now')),
    added_by TEXT DEFAULT 'SYSTEM'
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TEXT DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO config (key, value) VALUES
    ('auto_defense_enabled', 'true'),
    ('dry_run_mode', 'false'),
    ('brute_force_threshold', '5'),
    ('brute_force_window', '60');

CREATE TABLE IF NOT EXISTS vulnerability_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_time TEXT DEFAULT (datetime('now')),
    target TEXT,
    open_ports TEXT,
    vulnerabilities TEXT,
    raw_output TEXT
);
"""


class LogStorage:
    def __init__(self, db_path: str):
        self.db_path = db_path

    async def initialize(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(SCHEMA_SQL)
            await db.commit()
        logger.info(f"Database initialized at {self.db_path}")

    async def save_request(self, parsed: dict) -> int:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """INSERT INTO requests (timestamp, ip, method, path, status, size, user_agent, referrer, raw_log)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    parsed.get("timestamp", datetime.utcnow().isoformat()),
                    parsed.get("ip", ""),
                    parsed.get("method", ""),
                    parsed.get("path", ""),
                    parsed.get("status", 0),
                    parsed.get("size", 0),
                    parsed.get("user_agent", ""),
                    parsed.get("referrer", ""),
                    parsed.get("raw_log", ""),
                ),
            )
            await db.commit()
            return cursor.lastrowid

    async def mark_suspicious(self, request_id: int, attack_type: str, severity: str):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE requests SET is_suspicious=1, attack_type=?, severity=? WHERE id=?",
                (attack_type, severity, request_id),
            )
            await db.commit()

    async def mark_blocked(self, request_id: int):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("UPDATE requests SET blocked=1 WHERE id=?", (request_id,))
            await db.commit()

    async def save_analysis(self, request_id: int, attack_type: str, analysis: dict):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """INSERT INTO ai_analysis (request_id, attack_type, explanation, impact, mitigation, code_fix, refs)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    request_id,
                    attack_type,
                    analysis.get("explanation", ""),
                    analysis.get("impact", ""),
                    json.dumps(analysis.get("mitigation", [])),
                    json.dumps(analysis.get("code_fix", {})),
                    json.dumps(analysis.get("references", [])),
                ),
            )
            await db.commit()

    async def save_defense_action(self, action_type: str, ip: str, attack_type: str,
                                   severity: str, duration: int, status: str,
                                   details: str = "", performed_by: str = "SYSTEM"):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """INSERT INTO defense_actions (action_type, target_ip, attack_type, severity, duration, status, details, performed_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (action_type, ip, attack_type, severity, duration, status, details, performed_by),
            )
            await db.commit()

    async def add_blocked_ip(self, ip: str, attack_type: str, severity: str,
                              unblock_time: str, reason: str, blocked_by: str = "SYSTEM"):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """INSERT OR REPLACE INTO blocked_ips (ip, attack_type, severity, block_time, unblock_time, status, reason, blocked_by)
                   VALUES (?, ?, ?, datetime('now'), ?, 'ACTIVE', ?, ?)""",
                (ip, attack_type, severity, unblock_time, reason, blocked_by),
            )
            await db.commit()

    async def remove_blocked_ip(self, ip: str):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE blocked_ips SET status='UNBLOCKED' WHERE ip=? AND status='ACTIVE'", (ip,)
            )
            await db.commit()

    async def get_blocked_ips(self) -> List[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM blocked_ips WHERE status='ACTIVE' ORDER BY block_time DESC"
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    async def get_recent_attacks(self, limit: int = 50) -> List[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """SELECT r.*, a.explanation, a.impact, a.mitigation, a.code_fix, a.refs
                   FROM requests r
                   LEFT JOIN ai_analysis a ON a.request_id = r.id
                   WHERE r.is_suspicious=1
                   ORDER BY r.created_at DESC LIMIT ?""",
                (limit,),
            ) as cursor:
                rows = await cursor.fetchall()
                results = []
                for row in rows:
                    d = dict(row)
                    for field in ("mitigation", "code_fix", "refs"):
                        if d.get(field):
                            try:
                                d[field] = json.loads(d[field])
                            except Exception:
                                pass
                    results.append(d)
                return results

    async def get_attack_stats(self, days: int = 7) -> dict:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """SELECT attack_type, COUNT(*) as count FROM requests
                   WHERE is_suspicious=1 AND created_at >= datetime('now', ?)
                   GROUP BY attack_type""",
                (f"-{days} days",),
            ) as cursor:
                by_type = {row["attack_type"]: row["count"] for row in await cursor.fetchall()}

            async with db.execute(
                """SELECT severity, COUNT(*) as count FROM requests
                   WHERE is_suspicious=1 AND created_at >= datetime('now', ?)
                   GROUP BY severity""",
                (f"-{days} days",),
            ) as cursor:
                by_severity = {row["severity"]: row["count"] for row in await cursor.fetchall()}

            async with db.execute(
                """SELECT date(created_at) as date, COUNT(*) as count FROM requests
                   WHERE is_suspicious=1 AND created_at >= datetime('now', ?)
                   GROUP BY date(created_at) ORDER BY date""",
                (f"-{days} days",),
            ) as cursor:
                timeline = [{"date": row["date"], "count": row["count"]} for row in await cursor.fetchall()]

            async with db.execute(
                "SELECT COUNT(*) as total FROM requests WHERE is_suspicious=1 AND created_at >= datetime('now', ?)",
                (f"-{days} days",),
            ) as cursor:
                total = (await cursor.fetchone())["total"]

            async with db.execute(
                "SELECT COUNT(*) as blocked FROM requests WHERE blocked=1 AND created_at >= datetime('now', ?)",
                (f"-{days} days",),
            ) as cursor:
                blocked_count = (await cursor.fetchone())["blocked"]

        return {
            "total_attacks": total,
            "blocked_count": blocked_count,
            "by_type": by_type,
            "by_severity": by_severity,
            "timeline": timeline,
        }

    async def get_config(self, key: str) -> Optional[str]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT value FROM config WHERE key=?", (key,)) as cursor:
                row = await cursor.fetchone()
                return row["value"] if row else None

    async def set_config(self, key: str, value: str):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, datetime('now'))",
                (key, value),
            )
            await db.commit()

    async def save_scan_result(self, target: str, open_ports: list, vulnerabilities: list, raw: str):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO vulnerability_scans (target, open_ports, vulnerabilities, raw_output) VALUES (?, ?, ?, ?)",
                (target, json.dumps(open_ports), json.dumps(vulnerabilities), raw),
            )
            await db.commit()

    async def get_latest_scan(self) -> Optional[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM vulnerability_scans ORDER BY scan_time DESC LIMIT 1"
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    d = dict(row)
                    for f in ("open_ports", "vulnerabilities"):
                        try:
                            d[f] = json.loads(d[f])
                        except Exception:
                            pass
                    return d
                return None

    async def get_pending_unblocks(self) -> List[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM blocked_ips WHERE status='ACTIVE' AND unblock_time IS NOT NULL"
            ) as cursor:
                return [dict(r) for r in await cursor.fetchall()]
