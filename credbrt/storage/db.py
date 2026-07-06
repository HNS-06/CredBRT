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
    asn TEXT,
    device_id TEXT DEFAULT '',
    session_id TEXT DEFAULT '',
    geo_lat REAL DEFAULT 0,
    geo_lon REAL DEFAULT 0,
    response_time_ms INTEGER DEFAULT 0,
    endpoint TEXT DEFAULT '/login',
    http_method TEXT DEFAULT 'POST',
    failure_reason TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_attempts_ip ON attempts(ip);
CREATE INDEX IF NOT EXISTS idx_attempts_account ON attempts(account);
CREATE INDEX IF NOT EXISTS idx_attempts_ts ON attempts(ts);
CREATE INDEX IF NOT EXISTS idx_attempts_device ON attempts(device_id);

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

CREATE TABLE IF NOT EXISTS threat_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    source TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    added_at REAL NOT NULL,
    expires_at REAL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_threat_ip ON threat_intel(ip);

CREATE TABLE IF NOT EXISTS geo_anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT NOT NULL,
    ts REAL NOT NULL,
    ip_from TEXT NOT NULL,
    ip_to TEXT NOT NULL,
    country_from TEXT,
    country_to TEXT,
    distance_km REAL DEFAULT 0,
    time_gap_seconds REAL DEFAULT 0,
    impossible_travel INTEGER DEFAULT 0
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
            try:
                self.conn.commit()
            except sqlite3.OperationalError:
                pass  # No active transaction to commit (read-only query)
        finally:
            cur.close()

    def insert_attempt(self, attempt) -> int:
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO attempts (ts, ip, account, success, user_agent, country, asn, "
                "device_id, session_id, geo_lat, geo_lon, response_time_ms, endpoint, "
                "http_method, failure_reason) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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

    def insert_threat_intel(self, ip: str, source: str, threat_type: str,
                            confidence: float = 0.5, expires_at: float = 0) -> int:
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO threat_intel (ip, source, threat_type, confidence, added_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (ip, source, threat_type, confidence, time.time(), expires_at),
            )
            return cur.lastrowid

    def is_known_threat(self, ip: str) -> tuple[bool, str]:
        """Check if IP is in threat intel. Returns (is_threat, threat_type)."""
        now = time.time()
        with self.cursor() as cur:
            cur.execute(
                "SELECT threat_type FROM threat_intel WHERE ip=? AND (expires_at=0 OR expires_at>?)",
                (ip, now),
            )
            row = cur.fetchone()
            if row:
                return True, row[0]
            return False, ""

    def insert_geo_anomaly(self, account, ip_from, ip_to, country_from, country_to,
                           distance_km, time_gap_seconds):
        impossible = 1 if (distance_km > 500 and time_gap_seconds < 3600) else 0
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO geo_anomalies (account, ts, ip_from, ip_to, country_from, "
                "country_to, distance_km, time_gap_seconds, impossible_travel) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (account, time.time(), ip_from, ip_to, country_from, country_to,
                 distance_km, time_gap_seconds, impossible),
            )
            return impossible

    def recent_attempts(self, seconds: float = 300, limit: int = 5000):
        cutoff = time.time() - seconds
        with self.cursor() as cur:
            cur.execute(
                "SELECT ts, ip, account, success, user_agent, country, asn "
                "FROM attempts WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
                (cutoff, limit),
            )
            return cur.fetchall()

    def recent_attempts_full(self, seconds: float = 300, limit: int = 5000):
        cutoff = time.time() - seconds
        with self.cursor() as cur:
            cur.execute(
                "SELECT ts, ip, account, success, user_agent, country, asn, "
                "device_id, session_id, geo_lat, geo_lon, response_time_ms, "
                "endpoint, http_method, failure_reason "
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

    def devices_for_ip(self, ip: str, since: float):
        with self.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT device_id FROM attempts WHERE ip=? AND ts>=? AND device_id != ''",
                (ip, since),
            )
            return [r[0] for r in cur.fetchall()]

    def accounts_for_device(self, device_id: str, since: float):
        with self.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT account FROM attempts WHERE device_id=? AND ts>=?",
                (device_id, since),
            )
            return [r[0] for r in cur.fetchall()]

    def countries_for_ip(self, ip: str, since: float):
        with self.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT country FROM attempts WHERE ip=? AND ts>=? AND country != '??'",
                (ip, since),
            )
            return [r[0] for r in cur.fetchall()]

    def attempts_with_device(self, since: float):
        with self.cursor() as cur:
            cur.execute(
                "SELECT ts, ip, account, success, user_agent, country, asn, device_id "
                "FROM attempts WHERE ts>=? AND device_id != '' ORDER BY ts",
                (since,),
            )
            return cur.fetchall()

    def get_countries_for_account(self, account: str, since: float):
        with self.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT country, MIN(ts) as first_ts, MAX(ts) as last_ts "
                "FROM attempts WHERE account=? AND ts>=? AND country != '??' "
                "GROUP BY country",
                (account, since),
            )
            return cur.fetchall()

    def wipe(self):
        with self.cursor() as cur:
            cur.execute("DELETE FROM attempts")
            cur.execute("DELETE FROM alerts")
            cur.execute("DELETE FROM threat_intel")
            cur.execute("DELETE FROM geo_anomalies")

    def close(self):
        self.conn.close()
