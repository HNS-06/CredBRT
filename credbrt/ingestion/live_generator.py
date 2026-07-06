"""Live traffic generator — continuously produces realistic login traffic.

This runs in the background and generates a steady stream of normal
and suspicious login attempts, simulating a real environment.
"""
import random
import time
import threading
import sqlite3
from credbrt.storage.models import LoginAttempt
from credbrt.ingestion.simulator import (
    DESKTOP_UAS, MOBILE_UAS, BOT_UAS, GEO_LOCATIONS, REALISTIC_ACCOUNTS,
    FAILURE_REASONS, _generate_device_id, _generate_session_id, _rand_ip_from_pool,
)


class LiveTrafficGenerator:
    def __init__(self, db, rate_per_second: float = 2.0):
        self.db = db
        self.rate = rate_per_second
        self._running = False
        self._thread = None
        self._attack_cycle = 0
        self._active_sessions: dict[str, tuple[str, str]] = {}  # account -> (ip, session_id)
        self._thread_conn = None  # Separate connection for thread safety

    def _get_thread_conn(self):
        """Get a thread-local database connection."""
        if self._thread_conn is None:
            self._thread_conn = sqlite3.connect(str(self.db.path), check_same_thread=False)
            self._thread_conn.execute("PRAGMA journal_mode=WAL;")
        return self._thread_conn

    def _thread_insert(self, attempt):
        """Insert attempt using thread-local connection."""
        conn = self._get_thread_conn()
        conn.execute(
            "INSERT INTO attempts (ts, ip, account, success, user_agent, country, asn, "
            "device_id, session_id, geo_lat, geo_lon, response_time_ms, endpoint, "
            "http_method, failure_reason) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            attempt.to_row(),
        )
        conn.commit()

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def _run_loop(self):
        interval = 1.0 / self.rate
        while self._running:
            self._generate_one()
            time.sleep(interval + random.uniform(-0.1, 0.1))

    def _generate_one(self):
        self._attack_cycle += 1

        # Rotate between different traffic types
        phase = self._attack_cycle % 100

        if phase < 65:
            self._normal_login()
        elif phase < 75:
            self._suspicious_login()
        elif phase < 85:
            self._brute_force_attempt()
        elif phase < 92:
            self._spray_attempt()
        else:
            self._session_anomaly()

    def _normal_login(self):
        geo = random.choice(GEO_LOCATIONS[:10])
        is_mobile = random.random() < 0.35
        ua = random.choice(MOBILE_UAS if is_mobile else DESKTOP_UAS)
        account = random.choice(REALISTIC_ACCOUNTS[:20])

        # Check if this is a returning session
        if account in self._active_sessions and random.random() < 0.7:
            ip, session_id = self._active_sessions[account]
            success = random.random() > 0.05
        else:
            ip = _rand_ip_from_pool(f"{random.randint(1,223)}.{random.randint(0,255)}")
            session_id = _generate_session_id()
            success = random.random() > 0.08

        device_id = _generate_device_id(geo["city"], ua, account)

        attempt = LoginAttempt(
            ts=time.time(),
            ip=ip,
            account=account,
            success=success,
            user_agent=ua,
            country=geo["country"],
            asn=geo["asn"],
            device_id=device_id,
            session_id=session_id if success else "",
            geo_lat=geo["lat"] + random.uniform(-0.05, 0.05),
            geo_lon=geo["lon"] + random.uniform(-0.05, 0.05),
            response_time_ms=random.randint(30, 200),
            endpoint=random.choice(["/login", "/api/auth", "/signin"]),
            http_method="POST",
            failure_reason="" if success else random.choice(["invalid_password", "mfa_required"]),
        )
        self._thread_insert(attempt)

        if success:
            self._active_sessions[account] = (ip, session_id)

    def _suspicious_login(self):
        geo = random.choice(GEO_LOCATIONS[9:15])  # RU, CN, BR areas
        ua = random.choice(BOT_UAS)
        account = random.choice(REALISTIC_ACCOUNTS[:10])

        attempt = LoginAttempt(
            ts=time.time(),
            ip=_rand_ip_from_pool(f"{random.randint(185,220)}.{random.randint(1,254)}"),
            account=account,
            success=False,
            user_agent=ua,
            country=geo["country"],
            asn=geo["asn"],
            device_id="",
            session_id="",
            geo_lat=geo["lat"],
            geo_lon=geo["lon"],
            response_time_ms=random.randint(100, 500),
            endpoint="/login",
            http_method="POST",
            failure_reason=random.choice(["invalid_password", "account_locked", "ip_blocked"]),
        )
        self._thread_insert(attempt)

    def _brute_force_attempt(self):
        pool = random.choice([
            ("198.51.100", "RU", "AS40676"),
            ("185.220.101", "RU", "AS58002"),
            ("45.155.205", "RU", "AS200019"),
        ])
        ip = f"{pool[0]}.{random.randint(1,254)}"
        ua = random.choice(BOT_UAS)
        target = random.choice(["admin", "root", "test", "administrator"])

        for i in range(random.randint(3, 8)):
            attempt = LoginAttempt(
                ts=time.time() - i * random.uniform(0.5, 2),
                ip=ip,
                account=target,
                success=False,
                user_agent=ua,
                country=pool[1],
                asn=pool[2],
                device_id="",
                session_id="",
                geo_lat=55.76 + random.uniform(-2, 2),
                geo_lon=37.62 + random.uniform(-2, 2),
                response_time_ms=random.randint(100, 400),
                endpoint="/login",
                http_method="POST",
                failure_reason="invalid_password",
            )
            self._thread_insert(attempt)

    def _spray_attempt(self):
        pool = random.choice([
            ("185.220.100", "NL", "AS60781"),
            ("103.224.182", "CN", "AS138915"),
        ])
        ip = f"{pool[0]}.{random.randint(1,254)}"
        ua = random.choice(BOT_UAS)

        accounts = random.sample(REALISTIC_ACCOUNTS[:20], random.randint(3, 8))
        for i, acct in enumerate(accounts):
            attempt = LoginAttempt(
                ts=time.time() - i * random.uniform(2, 10),
                ip=ip,
                account=acct,
                success=False,
                user_agent=ua,
                country=pool[1],
                asn=pool[2],
                device_id="",
                session_id="",
                geo_lat=52.37 + random.uniform(-1, 1),
                geo_lon=4.90 + random.uniform(-1, 1),
                response_time_ms=random.randint(150, 600),
                endpoint="/api/auth",
                http_method="POST",
                failure_reason="invalid_password",
            )
            self._thread_insert(attempt)

    def _session_anomaly(self):
        """Same session used from different locations."""
        account = random.choice(REALISTIC_ACCOUNTS[5:15])
        if account not in self._active_sessions:
            return

        legit_ip, session_id = self._active_sessions[account]
        hijack_ip = f"45.155.205.{random.randint(1,254)}"

        attempt = LoginAttempt(
            ts=time.time(),
            ip=hijack_ip,
            account=account,
            success=True,
            user_agent=random.choice(BOT_UAS),
            country="RU",
            asn="AS40676",
            device_id=_generate_device_id("Moscow", BOT_UAS[0], "hijack"),
            session_id=session_id,
            geo_lat=55.76,
            geo_lon=37.62,
            response_time_ms=random.randint(80, 300),
            endpoint=random.choice(["/admin", "/api/data", "/export"]),
            http_method="GET",
            failure_reason="",
        )
        self._thread_insert(attempt)
