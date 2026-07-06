"""SQLite storage layer — WAL mode for concurrent read while ingesting."""
import sqlite3
import time
from pathlib import Path
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    ip TEXT NOT NULL,
    account TEXT NOT NULL,
    success INTEGER NOT NULL,
    user_agent TEXT,
    country TEXT,
    asn TEXT
);
CREATE INDEX IF NOT EXISTS idx_attempts_ip ON attempts(ip);
CREATE INDEX IF NOT EXISTS idx_attempts_account ON attempts(account);
CREATE INDEX IF NOT EXISTS idx_attempts_ts ON attempts(ts);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    entity TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    score REAL NOT NULL,
    tier TEXT NOT NULL,
    reason TEXT
);

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip TEXT PRIMARY KEY,
    reputation_score REAL DEFAULT 0,
    last_checked REAL,
    notes TEXT
);
"""


class Database:
    def __init__(self, path: str = "credbrt.db"):
        self.path = Path(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    @contextmanager
    def cursor(self):
        cur = self.conn.cursor()
        try:
            yield cur
            self.conn.commit()
        finally:
            cur.close()

    def insert_attempt(self, attempt) -> int:
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO attempts (ts, ip, account, success, user_agent, country, asn) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                attempt.to_row(),
            )
            return cur.lastrowid

    def insert_alert(self, alert) -> int:
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO alerts (ts, entity, entity_type, score, tier, reason) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (alert.ts, alert.entity, alert.entity_type, alert.score, alert.tier, alert.reason),
            )
            return cur.lastrowid

    def recent_attempts(self, seconds: float = 300, limit: int = 5000):
        cutoff = time.time() - seconds
        with self.cursor() as cur:
            cur.execute(
                "SELECT ts, ip, account, success, user_agent, country, asn "
                "FROM attempts WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
                (cutoff, limit),
            )
            return cur.fetchall()

    def recent_alerts(self, limit: int = 50):
        with self.cursor() as cur:
            cur.execute(
                "SELECT ts, entity, entity_type, score, tier, reason "
                "FROM alerts ORDER BY ts DESC LIMIT ?",
                (limit,),
            )
            return cur.fetchall()

    def failed_attempts_by_ip(self, ip: str, since: float):
        with self.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM attempts WHERE ip=? AND success=0 AND ts>=?",
                (ip, since),
            )
            return cur.fetchone()[0]

    def distinct_accounts_for_ip(self, ip: str, since: float):
        with self.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT account FROM attempts WHERE ip=? AND ts>=?",
                (ip, since),
            )
            return [r[0] for r in cur.fetchall()]

    def distinct_ips_for_account(self, account: str, since: float):
        with self.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT ip FROM attempts WHERE account=? AND ts>=?",
                (account, since),
            )
            return [r[0] for r in cur.fetchall()]

    def all_timestamps_for_account(self, account: str, since: float):
        with self.cursor() as cur:
            cur.execute(
                "SELECT ts FROM attempts WHERE account=? AND success=0 AND ts>=? ORDER BY ts",
                (account, since),
            )
            return [r[0] for r in cur.fetchall()]

    def user_agents_for_ip(self, ip: str, since: float):
        with self.cursor() as cur:
            cur.execute(
                "SELECT user_agent FROM attempts WHERE ip=? AND ts>=?",
                (ip, since),
            )
            return [r[0] for r in cur.fetchall()]

    def wipe(self):
        with self.cursor() as cur:
            cur.execute("DELETE FROM attempts")
            cur.execute("DELETE FROM alerts")

    def close(self):
        self.conn.close()
