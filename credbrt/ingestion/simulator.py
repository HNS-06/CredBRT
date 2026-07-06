"""Realistic synthetic login-traffic generator.

Generates realistic-looking login traffic with proper geolocations,
user-agents, device fingerprints, session tokens, timing patterns,
and failure modes — for testing detection engines against realistic data.
"""
import random
import hashlib
import time
import math
from credbrt.storage.models import LoginAttempt

# Realistic user agents (current market share ~2024-2025)
DESKTOP_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

MOBILE_UAS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/124.0.6367.88 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
]

BOT_UAS = [
    "python-requests/2.31.0",
    "python-requests/2.28.1",
    "curl/8.4.0",
    "curl/7.88.1",
    "Go-http-client/1.1",
    "Go-http-client/2.0",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "sqlmap/1.7.12#stable (https://sqlmap.org)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
    "python-urllib/3.11",
    "Java/17.0.2",
    "okhttp/4.12.0",
    "Scrapy/2.11.0",
]

# Realistic geo-locations with ISPs
GEO_LOCATIONS = [
    {"country": "US", "asn": "AS7922", "city": "New York", "lat": 40.71, "lon": -74.01, "isp": "Comcast"},
    {"country": "US", "asn": "AS7922", "city": "Chicago", "lat": 41.88, "lon": -87.63, "isp": "Comcast"},
    {"country": "US", "asn": "AS22394", "city": "Los Angeles", "lat": 34.05, "lon": -118.24, "isp": "Verizon"},
    {"country": "US", "asn": "AS7018", "city": "Houston", "lat": 29.76, "lon": -95.37, "isp": "AT&T"},
    {"country": "US", "asn": "AS701", "city": "Phoenix", "lat": 33.45, "lon": -112.07, "isp": "CenturyLink"},
    {"country": "GB", "asn": "AS2856", "city": "London", "lat": 51.51, "lon": -0.13, "isp": "BT"},
    {"country": "DE", "asn": "AS3320", "city": "Berlin", "lat": 52.52, "lon": 13.41, "isp": "Deutsche Telekom"},
    {"country": "FR", "asn": "AS3215", "city": "Paris", "lat": 48.86, "lon": 2.35, "isp": "Orange"},
    {"country": "NL", "asn": "AS1136", "city": "Amsterdam", "lat": 52.37, "lon": 4.90, "isp": "KPN"},
    {"country": "RU", "asn": "AS47541", "city": "Moscow", "lat": 55.76, "lon": 37.62, "isp": "VK"},
    {"country": "RU", "asn": "AS58002", "city": "Saint Petersburg", "lat": 59.93, "lon": 30.32, "isp": "Selectel"},
    {"country": "CN", "asn": "AS4134", "city": "Beijing", "lat": 39.90, "lon": 116.40, "isp": "ChinaNet"},
    {"country": "CN", "asn": "AS4837", "city": "Shanghai", "lat": 31.23, "lon": 121.47, "isp": "ChinaUnicom"},
    {"country": "BR", "asn": "AS28573", "city": "Sao Paulo", "lat": -23.55, "lon": -46.63, "isp": "Claro"},
    {"country": "IN", "asn": "AS9829", "city": "Mumbai", "lat": 19.08, "lon": 72.88, "isp": "BSNL"},
    {"country": "JP", "asn": "AS2497", "city": "Tokyo", "lat": 35.68, "lon": 139.69, "isp": "IIJ"},
    {"country": "AU", "asn": "AS4826", "city": "Sydney", "lat": -33.87, "lon": 151.21, "isp": "Telstra"},
    {"country": "CA", "asn": "AS577", "city": "Toronto", "lat": 43.65, "lon": -79.38, "isp": "Bell"},
    {"country": "KR", "asn": "AS4766", "city": "Seoul", "lat": 37.57, "lon": 126.98, "isp": "KIXS"},
    {"country": "UA", "asn": "AS15895", "city": "Kyiv", "lat": 50.45, "lon": 30.52, "isp": "Kyivstar"},
]

# Known malicious IP ranges (for realistic threat simulation)
ATTACKER_IPS = {
    "bruteforce": [
        ("198.51.100", "RU", "AS40676", "Moscow"),
        ("185.220.101", "RU", "AS58002", "St Petersburg"),
        ("45.155.205", "RU", "AS200019", "Moscow"),
        ("91.240.118", "UA", "AS205018", "Kharkiv"),
    ],
    "spray": [
        ("185.220.100", "NL", "AS60781", "Amsterdam"),
        ("103.224.182", "CN", "AS138915", "Beijing"),
        ("159.89.167", "DE", "AS14061", "Frankfurt"),
    ],
    "stuffing": [
        ("91.240.119", "UA", "AS47763", "Kyiv"),
        ("45.148.10", "RU", "AS48693", "Moscow"),
        ("103.152.220", "CN", "AS38283", "Shanghai"),
    ],
    "lowandslow": [
        ("192.168.1", "US", "AS0", "Local"),
        ("10.0.0", "US", "AS0", "Internal"),
    ],
}

# Realistic usernames
REALISTIC_ACCOUNTS = [
    "admin", "administrator", "root", "test", "demo",
    "john.smith", "jane.doe", "mike.jones", "sarah.williams",
    "david.brown", "emily.davis", "chris.miller", "jessica.wilson",
    "alex.johnson", "rachel.anderson", "tom.thomas", "lisa.jackson",
    "user1", "user2", "user3", "support", "helpdesk",
    "jsmith", "jdoe", "mjones", "swilliams",
    "admin@company.com", "john@corp.io", "devops@team.org",
    "backup.admin", "sysadmin", "dev_admin",
]

# Realistic failure reasons
FAILURE_REASONS = [
    "invalid_password",
    "account_locked",
    "mfa_required",
    "account_disabled",
    "expired_password",
    "invalid_username",
    "too_many_attempts",
    "ip_blocked",
    "geo_restricted",
    "device_not_recognized",
]


def _generate_device_id(ip: str, ua: str, salt: str = "") -> str:
    """Generate a deterministic device fingerprint hash."""
    raw = f"{ip}:{ua}:{salt}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _generate_session_id() -> str:
    """Generate a random session token."""
    return hashlib.md5(str(random.random()).encode()).hexdigest()[:12]


def _human_timing(mean_interval: float = 3.0) -> float:
    """Generate human-like timing with bursty intervals."""
    if random.random() < 0.3:
        return random.expovariate(1.0 / (mean_interval * 3))
    return random.expovariate(1.0 / mean_interval)


def _bot_timing(interval: float = 2.0) -> float:
    """Generate bot-like regular timing with slight jitter."""
    return interval + random.uniform(-0.2, 0.2)


def _rand_ip_from_pool(pool_prefix: str = "203.0") -> str:
    return f"{pool_prefix}.{random.randint(1,254)}.{random.randint(1,254)}"


class Simulator:
    def __init__(self, db):
        self.db = db

    def normal_traffic(self, n: int = 80):
        """Baseline benign logins — real users with normal behavior."""
        now = time.time()
        accounts = random.sample(REALISTIC_ACCOUNTS, min(15, len(REALISTIC_ACCOUNTS)))

        for i in range(n):
            geo = random.choice(GEO_LOCATIONS[:10])  # bias towards US/EU for normal
            is_mobile = random.random() < 0.35
            ua = random.choice(MOBILE_UAS if is_mobile else DESKTOP_UAS)
            account = random.choice(accounts)
            device_id = _generate_device_id(geo["city"], ua, account)

            # Real users mostly succeed (92% success rate)
            success = random.random() > 0.08
            failure_reason = "" if success else random.choice([
                "invalid_password", "mfa_required"
            ])

            attempt = LoginAttempt(
                ts=now - random.uniform(0, 1800),  # spread over 30 min
                ip=_rand_ip_from_pool(f"{random.randint(1,223)}.{random.randint(0,255)}"),
                account=account,
                success=success,
                user_agent=ua,
                country=geo["country"],
                asn=geo["asn"],
                device_id=device_id,
                session_id=_generate_session_id(),
                geo_lat=geo["lat"] + random.uniform(-0.05, 0.05),
                geo_lon=geo["lon"] + random.uniform(-0.05, 0.05),
                response_time_ms=random.randint(45, 350),
                endpoint=random.choice(["/login", "/api/auth", "/signin"]),
                http_method="POST",
                failure_reason=failure_reason,
            )
            self.db.insert_attempt(attempt)

    def brute_force(self, n: int = 25):
        """Single IP hammering a single account — classic loud brute force."""
        pool = random.choice(ATTACKER_IPS["bruteforce"])
        ip_prefix, country, asn, city = pool
        ip = f"{ip_prefix}.{random.randint(1,254)}"
        target_account = random.choice(["admin", "root", "administrator", "test"])

        # Attacker uses a bot
        ua = random.choice(BOT_UAS)
        device_id = _generate_device_id(ip, ua, "attacker")

        now = time.time()
        for i in range(n):
            # Speeds up over time (impatient attacker)
            interval = max(0.5, 3.0 - (i * 0.15))
            attempt = LoginAttempt(
                ts=now - (n - i) * interval,
                ip=ip,
                account=target_account,
                success=False,
                user_agent=ua,
                country=country,
                asn=asn,
                device_id=device_id,
                session_id="",
                geo_lat=GEO_LOCATIONS[9]["lat"] + random.uniform(-1, 1),
                geo_lon=GEO_LOCATIONS[9]["lon"] + random.uniform(-1, 1),
                response_time_ms=random.randint(100, 500),
                endpoint="/login",
                http_method="POST",
                failure_reason="invalid_password",
            )
            self.db.insert_attempt(attempt)

    def password_spray(self, n_accounts: int = 15):
        """One IP, many accounts, one attempt each — spray pattern."""
        pool = random.choice(ATTACKER_IPS["spray"])
        ip_prefix, country, asn, city = pool
        ip = f"{ip_prefix}.{random.randint(1,254)}"

        ua = random.choice(BOT_UAS)
        device_id = _generate_device_id(ip, ua, "sprayer")

        now = time.time()
        target_accounts = random.sample(REALISTIC_ACCOUNTS, n_accounts)

        for i, acct in enumerate(target_accounts):
            attempt = LoginAttempt(
                ts=now - i * random.uniform(2, 8),
                ip=ip,
                account=acct,
                success=False,
                user_agent=ua,
                country=country,
                asn=asn,
                device_id=device_id,
                session_id="",
                geo_lat=GEO_LOCATIONS[10]["lat"] + random.uniform(-2, 2),
                geo_lon=GEO_LOCATIONS[10]["lon"] + random.uniform(-2, 2),
                response_time_ms=random.randint(150, 600),
                endpoint=random.choice(["/login", "/api/auth"]),
                http_method="POST",
                failure_reason="invalid_password",
            )
            self.db.insert_attempt(attempt)

    def credential_stuffing_low_and_slow(self, account: str = None, n_ips: int = 18):
        """Many distinct IPs, each trying the same account a couple times,
        spread thinly over a wide window — the pattern that velocity-only
        rate limiters miss."""
        account = account or random.choice(REALISTIC_ACCOUNTS[:5])
        now = time.time()

        for i in range(n_ips):
            pool = random.choice(ATTACKER_IPS["stuffing"])
            ip_prefix, country, asn, city = pool
            ip = f"{ip_prefix}.{random.randint(1,254)}"

            # Each IP uses a different UA to evade fingerprinting
            ua = random.choice(BOT_UAS)
            device_id = _generate_device_id(ip, ua, f"stuff_{i}")

            for j in range(random.randint(1, 3)):  # 1-3 attempts per IP
                attempt = LoginAttempt(
                    ts=now - random.uniform(0, 3600),  # spread over 1 hour
                    ip=ip,
                    account=account,
                    success=False,
                    user_agent=ua,
                    country=country,
                    asn=asn,
                    device_id=device_id,
                    session_id="",
                    geo_lat=GEO_LOCATIONS[11 + (i % 3)]["lat"] + random.uniform(-5, 5),
                    geo_lon=GEO_LOCATIONS[11 + (i % 3)]["lon"] + random.uniform(-5, 5),
                    response_time_ms=random.randint(200, 800),
                    endpoint="/api/auth/login",
                    http_method="POST",
                    failure_reason="invalid_password",
                )
                self.db.insert_attempt(attempt)

    def geo_anomaly_pattern(self, account: str = "john.smith"):
        """Simulate impossible travel — same account from distant locations in short time."""
        now = time.time()
        locations = random.sample(GEO_LOCATIONS, 4)

        for i, geo in enumerate(locations):
            ua = random.choice(DESKTOP_UAS if random.random() > 0.5 else MOBILE_UAS)
            attempt = LoginAttempt(
                ts=now - (len(locations) - i) * random.uniform(30, 300),
                ip=_rand_ip_from_pool(f"{random.randint(100,200)}.{random.randint(1,254)}"),
                account=account,
                success=random.random() > 0.3,
                user_agent=ua,
                country=geo["country"],
                asn=geo["asn"],
                device_id=_generate_device_id(geo["city"], ua, account),
                session_id=_generate_session_id(),
                geo_lat=geo["lat"],
                geo_lon=geo["lon"],
                response_time_ms=random.randint(50, 400),
                endpoint="/login",
                http_method="POST",
                failure_reason="" if random.random() > 0.3 else "device_not_recognized",
            )
            self.db.insert_attempt(attempt)

    def session_hijacking_pattern(self, n_attempts: int = 20):
        """Simulate session hijacking — same session used from different IPs/devices."""
        now = time.time()
        session_id = _generate_session_id()
        account = random.choice(REALISTIC_ACCOUNTS[5:15])
        legitimate_ip = f"73.162.{random.randint(1,254)}.{random.randint(1,254)}"

        # Normal user activity first
        for i in range(5):
            attempt = LoginAttempt(
                ts=now - 600 + i * _human_timing(30),
                ip=legitimate_ip,
                account=account,
                success=True,
                user_agent=random.choice(DESKTOP_UAS),
                country="US",
                asn="AS7922",
                device_id=_generate_device_id("NYC", DESKTOP_UAS[0], account),
                session_id=session_id,
                geo_lat=40.71 + random.uniform(-0.1, 0.1),
                geo_lon=-74.01 + random.uniform(-0.1, 0.1),
                response_time_ms=random.randint(30, 120),
                endpoint=random.choice(["/dashboard", "/api/data", "/profile"]),
                http_method="GET",
                failure_reason="",
            )
            self.db.insert_attempt(attempt)

        # Then attacker hijacks the session
        hijack_ip = f"45.155.205.{random.randint(1,254)}"
        for i in range(n_attempts - 5):
            attempt = LoginAttempt(
                ts=now - 300 + i * _bot_timing(5),
                ip=hijack_ip,
                account=account,
                success=True,  # session is valid!
                user_agent=random.choice(BOT_UAS),
                country="RU",
                asn="AS40676",
                device_id=_generate_device_id("Moscow", BOT_UAS[0], "hijacker"),
                session_id=session_id,  # same session from different IP!
                geo_lat=55.76 + random.uniform(-1, 1),
                geo_lon=37.62 + random.uniform(-1, 1),
                response_time_ms=random.randint(80, 300),
                endpoint=random.choice(["/admin", "/api/admin/users", "/api/export"]),
                http_method=random.choice(["GET", "POST", "DELETE"]),
                failure_reason="",
            )
            self.db.insert_attempt(attempt)

    def run_all_demo_patterns(self):
        """Run a comprehensive realistic demo."""
        self.normal_traffic(100)
        self.brute_force(25)
        self.password_spray(15)
        self.credential_stuffing_low_and_slow(n_ips=18)
        self.geo_anomaly_pattern("john.smith")
        self.session_hijacking_pattern(20)
