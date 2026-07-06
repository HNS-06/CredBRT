"""Velocity detector — classic sliding-window brute force detection.

Catches the 'loud' attacker: many failed attempts against one IP or
one account within a short time window.
"""
import time


class VelocityDetector:
    def __init__(self, db, cfg: dict):
        self.db = db
        self.window = cfg["velocity_window_seconds"]
        self.ip_threshold = cfg["velocity_fail_threshold"]
        self.account_threshold = cfg["account_fail_threshold"]

    def score_ip(self, ip: str) -> tuple[float, list[str]]:
        """Return (0-100 sub-score, reasons) for a single IP's velocity."""
        since = time.time() - self.window
        fails = self.db.failed_attempts_by_ip(ip, since)
        if fails == 0:
            return 0.0, []
        ratio = fails / self.ip_threshold
        score = min(100.0, ratio * 100.0)
        reasons = []
        if fails >= self.ip_threshold:
            reasons.append(f"{fails} failed logins from {ip} in {self.window}s (threshold {self.ip_threshold})")
        return score, reasons

    def score_account(self, account: str) -> tuple[float, list[str]]:
        since = time.time() - self.window
        ts_list = self.db.all_timestamps_for_account(account, since)
        fails = len(ts_list)
        if fails == 0:
            return 0.0, []
        ratio = fails / self.account_threshold
        score = min(100.0, ratio * 100.0)
        reasons = []
        if fails >= self.account_threshold:
            reasons.append(f"{fails} failed logins against account '{account}' in {self.window}s")
        return score, reasons
