"""Behavioral fingerprinting — separates scripted bot traffic from humans.

Signals:
  - User-agent diversity per IP: real browsers rarely rotate UA strings;
    automated tools/credential-stuffing kits often rotate UAs to evade
    naive fingerprint-based blocking.
  - Timing-interval variance: humans have irregular, "bursty" typing/retry
    behavior; scripts fire at suspiciously regular intervals (low variance).
"""
import statistics
import time


class FingerprintDetector:
    def __init__(self, db, cfg: dict):
        self.db = db
        self.window = cfg["velocity_window_seconds"] * 5
        self.min_samples = cfg["fingerprint_min_samples"]

    def score_ip(self, ip: str) -> tuple[float, list[str]]:
        since = time.time() - self.window
        uas = self.db.user_agents_for_ip(ip, since)
        if len(uas) < self.min_samples:
            return 0.0, []

        distinct_ua_ratio = len(set(uas)) / len(uas)

        with self.db.cursor() as cur:
            cur.execute(
                "SELECT ts FROM attempts WHERE ip=? AND ts>=? ORDER BY ts", (ip, since)
            )
            timestamps = [r[0] for r in cur.fetchall()]

        interval_score = 0.0
        cv = None
        if len(timestamps) >= self.min_samples:
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
            if len(intervals) >= 2 and statistics.mean(intervals) > 0:
                cv = statistics.pstdev(intervals) / statistics.mean(intervals)  # coefficient of variation
                # low variance (cv near 0) => suspiciously regular => scripted
                interval_score = max(0.0, 100.0 * (1 - min(cv, 1.0)))

        ua_score = min(100.0, distinct_ua_ratio * 150.0)  # rotating UAs is a strong signal

        combined = (ua_score * 0.5) + (interval_score * 0.5)
        reasons = []
        if distinct_ua_ratio > 0.5 and len(uas) >= self.min_samples:
            reasons.append(f"IP {ip} rotated user-agents across {len(set(uas))} distinct "
                            f"values in {len(uas)} attempts (evasion signal)")
        if interval_score > 70:
            cv_str = f"{cv:.2f}" if cv is not None else "n/a"
            reasons.append(f"IP {ip} shows highly regular request timing "
                            f"(automation signal, cv={cv_str})")
        return combined, reasons
