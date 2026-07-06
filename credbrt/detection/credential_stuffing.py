"""Credential stuffing / password spray detector.

Two attack shapes, both graph fan-out/fan-in problems:
  - SPRAY:     1 source IP  -> many distinct accounts   (fan-out)
  - STUFFING:  1 target account -> many distinct source IPs (fan-in)

Neither shape necessarily trips a simple per-IP rate limit, since each
individual account/IP pairing may see very few attempts.
"""
import time


class CredentialStuffingDetector:
    def __init__(self, db, cfg: dict):
        self.db = db
        self.window = cfg["velocity_window_seconds"] * 5  # wider window than raw velocity
        self.fanout_threshold = cfg["stuffing_ip_fanout_threshold"]
        self.fanin_threshold = cfg["stuffing_account_fanin_threshold"]

    def score_ip_fanout(self, ip: str) -> tuple[float, list[str]]:
        """Detect password-spray: one IP hitting many distinct accounts."""
        since = time.time() - self.window
        accounts = self.db.distinct_accounts_for_ip(ip, since)
        n = len(accounts)
        if n == 0:
            return 0.0, []
        score = min(100.0, (n / self.fanout_threshold) * 100.0)
        reasons = []
        if n >= self.fanout_threshold:
            reasons.append(f"IP {ip} attempted logins against {n} distinct accounts "
                            f"in {self.window}s (spray pattern)")
        return score, reasons

    def score_account_fanin(self, account: str) -> tuple[float, list[str]]:
        """Detect credential stuffing: one account targeted from many distinct IPs."""
        since = time.time() - self.window
        ips = self.db.distinct_ips_for_account(account, since)
        n = len(ips)
        if n == 0:
            return 0.0, []
        score = min(100.0, (n / self.fanin_threshold) * 100.0)
        reasons = []
        if n >= self.fanin_threshold:
            reasons.append(f"Account '{account}' targeted from {n} distinct IPs "
                            f"in {self.window}s (distributed stuffing pattern)")
        return score, reasons
