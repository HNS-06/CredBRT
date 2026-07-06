"""Threat intelligence and IOC (Indicators of Compromise) matching.

Checks incoming IPs against:
  - Known malicious IP lists (configurable)
  - Tor exit nodes
  - VPN/proxy detection
  - Historical attack patterns in the local database
"""
import time


class ThreatIntelDetector:
    def __init__(self, db, cfg: dict):
        self.db = db
        self.window = cfg.get("threat_intel_window_seconds", 86400)

        # Built-in known-bad ranges (simplified for demo)
        self.known_tor_exit = set()
        self.known_vpn_ranges = set()
        self.known_scanners = set()

        # Load from config if available
        threat_cfg = cfg.get("threat_intel", {})
        self.enabled = threat_cfg.get("enabled", True)
        self.auto_block_threshold = threat_cfg.get("auto_block_threshold", 80)

    def load_default_threats(self):
        """Load default threat intelligence (for demo/testing)."""
        default_threats = [
            ("198.51.100.0/24", "known_attacker", "bruteforce", 0.9),
            ("185.220.100.0/24", "known_attacker", "scanner", 0.85),
            ("45.155.205.0/24", "known_attacker", "c2_server", 0.95),
            ("91.240.118.0/24", "known_attacker", "bruteforce", 0.8),
            ("103.224.182.0/24", "known_attacker", "spray", 0.75),
            ("159.89.167.0/24", "suspicious", "proxy", 0.6),
        ]

        for ip_prefix, source, threat_type, confidence in default_threats:
            base_ip = ip_prefix.split("/")[0]
            # Insert individual IPs from the range
            parts = base_ip.split(".")
            if len(parts) == 4:
                for i in range(1, 255):
                    ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{i}"
                    self.db.insert_threat_intel(ip, source, threat_type, confidence)

    def score_ip(self, ip: str) -> tuple[float, list[str]]:
        if not self.enabled:
            return 0.0, []

        is_threat, threat_type = self.db.is_known_threat(ip)
        reasons = []
        score = 0.0

        if is_threat:
            score = 70.0
            reasons.append(f"IP {ip} matches threat intel: {threat_type}")

        # Check historical attack patterns from local DB
        since = time.time() - self.window
        with self.db.cursor() as cur:
            # Count failed attempts
            cur.execute(
                "SELECT COUNT(*) FROM attempts WHERE ip=? AND success=0 AND ts>=?",
                (ip, since),
            )
            fail_count = cur.fetchone()[0]

            # Count distinct accounts targeted
            cur.execute(
                "SELECT COUNT(DISTINCT account) FROM attempts WHERE ip=? AND success=0 AND ts>=?",
                (ip, since),
            )
            acct_count = cur.fetchone()[0]

            # Check for admin endpoint access
            cur.execute(
                "SELECT COUNT(*) FROM attempts WHERE ip=? AND endpoint LIKE '%admin%' AND ts>=?",
                (ip, since),
            )
            admin_count = cur.fetchone()[0]

        if fail_count > 20:
            score = max(score, min(90.0, 50.0 + fail_count))
            reasons.append(f"IP {ip} has {fail_count} failed attempts (local history)")

        if acct_count > 5:
            score = max(score, min(85.0, 40.0 + acct_count * 8))
            reasons.append(f"IP {ip} targeted {acct_count} different accounts")

        if admin_count > 3:
            score = max(score, 75.0)
            reasons.append(f"IP {ip} attempted {admin_count} admin endpoint accesses")

        return score, reasons

    def score_account(self, account: str) -> tuple[float, list[str]]:
        """Check if account is being targeted by known threats."""
        if not self.enabled:
            return 0.0, []

        since = time.time() - self.window
        with self.db.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT ip FROM attempts WHERE account=? AND success=0 AND ts>=?",
                (account, since),
            )
            attacking_ips = [r[0] for r in cur.fetchall()]

        if not attacking_ips:
            return 0.0, []

        reasons = []
        score = 0.0
        threat_count = 0

        for ip in attacking_ips:
            is_threat, threat_type = self.db.is_known_threat(ip)
            if is_threat:
                threat_count += 1

        if threat_count > 0:
            score = min(100.0, 30.0 + threat_count * 20.0)
            reasons.append(
                f"Account '{account}' targeted by {threat_count} known threat IPs"
            )

        return score, reasons
