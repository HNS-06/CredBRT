"""Synthetic login-traffic generator.

This does NOT attack anything — it fabricates LoginAttempt records
directly into your local database so you can validate that your own
detectors fire correctly, the same way you'd write unit-test fixtures.
Think of it as a traffic replay/fixture generator for the detection
engine, not an attack tool.
"""
import random
import time
from credbrt.storage.models import LoginAttempt

NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Safari/605.1",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0",
]
BOT_UAS = [
    "python-requests/2.31", "curl/8.4.0", "Go-http-client/1.1",
    "Mozilla/5.0 (compatible; scanner)", "okhttp/4.9",
]


def _rand_ip(pool_prefix="45.33"):
    return f"{pool_prefix}.{random.randint(1,254)}.{random.randint(1,254)}"


class Simulator:
    def __init__(self, db):
        self.db = db

    def normal_traffic(self, n: int = 50):
        """Baseline benign logins — mostly successes, a handful of typos."""
        now = time.time()
        for _ in range(n):
            success = random.random() > 0.08
            attempt = LoginAttempt(
                ts=now - random.uniform(0, 600),
                ip=_rand_ip("203.0"),
                account=random.choice(["alice", "bob", "carol", "dave", "erin"]),
                success=success,
                user_agent=random.choice(NORMAL_UAS),
                country="US",
                asn="AS15169",
            )
            self.db.insert_attempt(attempt)

    def brute_force(self, ip: str = None, account: str = "victim1", n: int = 15):
        """Single IP hammering a single account — classic loud brute force."""
        ip = ip or _rand_ip("198.51")
        now = time.time()
        for i in range(n):
            attempt = LoginAttempt(
                ts=now - (n - i) * 2,   # every ~2 seconds
                ip=ip, account=account, success=False,
                user_agent=random.choice(BOT_UAS), country="RU", asn="AS40676",
            )
            self.db.insert_attempt(attempt)

    def password_spray(self, ip: str = None, n_accounts: int = 10):
        """One IP, many accounts, one attempt each — spray pattern."""
        ip = ip or _rand_ip("185.220")
        now = time.time()
        accounts = [f"user{i}" for i in range(n_accounts)]
        for i, acct in enumerate(accounts):
            attempt = LoginAttempt(
                ts=now - i * 3, ip=ip, account=acct, success=False,
                user_agent=random.choice(BOT_UAS), country="NL", asn="AS60781",
            )
            self.db.insert_attempt(attempt)

    def credential_stuffing_low_and_slow(self, account: str = "victim2", n_ips: int = 12):
        """Many distinct IPs, each trying the same account a couple times,
        spread thinly over a wide window — this is what velocity-only
        rate limiters miss, and what the low-and-slow detector targets."""
        now = time.time()
        for i in range(n_ips):
            ip = _rand_ip(f"91.{i%255}")
            for j in range(2):  # only 2 attempts per IP — stays under any per-IP threshold
                attempt = LoginAttempt(
                    ts=now - random.uniform(0, 3000),
                    ip=ip, account=account, success=False,
                    user_agent=random.choice(BOT_UAS), country="CN", asn="AS4134",
                )
                self.db.insert_attempt(attempt)

    def run_all_demo_patterns(self):
        self.normal_traffic(60)
        self.brute_force()
        self.password_spray()
        self.credential_stuffing_low_and_slow()
