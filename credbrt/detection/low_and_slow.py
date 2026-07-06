"""Low-and-slow distributed attack detector.

The key gap this fills: a simple rate limiter only looks at a single
IP's request rate. A patient attacker spreads attempts across dozens
of IPs at a low per-IP rate, so no single source ever crosses a naive
threshold. This module looks at the *account* as the unit of analysis
across ALL its source IPs combined, using:

  1. An EWMA of the account's failure rate over a long rolling window,
     so a slow drip of failures still accumulates "heat" over time.
  2. A source-IP diversity/entropy score — many distinct IPs each
     contributing a little bit of failure activity is far more
     suspicious than the same handful of IPs.
"""
import math
import time
from collections import Counter


class LowAndSlowDetector:
    def __init__(self, db, cfg: dict):
        self.db = db
        self.window = cfg["low_and_slow_window_seconds"]
        self.alpha = cfg["low_and_slow_ewma_alpha"]
        self.ip_diversity_threshold = cfg["low_and_slow_ip_diversity_threshold"]
        self._ewma_state: dict[str, float] = {}

    def _update_ewma(self, key: str, sample: float) -> float:
        prev = self._ewma_state.get(key, sample)
        new = self.alpha * sample + (1 - self.alpha) * prev
        self._ewma_state[key] = new
        return new

    @staticmethod
    def _shannon_entropy(counts: list[int]) -> float:
        total = sum(counts)
        if total == 0:
            return 0.0
        entropy = 0.0
        for c in counts:
            p = c / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def score_account(self, account: str) -> tuple[float, list[str]]:
        since = time.time() - self.window
        fail_ts = self.db.all_timestamps_for_account(account, since)
        ips = self.db.distinct_ips_for_account(account, since)

        if not fail_ts:
            return 0.0, []

        # 1. long-window failure heat via EWMA (bucketed per 5 min)
        bucket_seconds = 300
        now = time.time()
        bucket_idx = int(now // bucket_seconds)
        buckets = Counter(int(t // bucket_seconds) for t in fail_ts)
        sample = buckets.get(bucket_idx, 0) + buckets.get(bucket_idx - 1, 0)
        heat = self._update_ewma(f"acct:{account}", sample)

        # 2. IP diversity — entropy of failures across distinct source IPs
        with self.db.cursor() as cur:
            cur.execute(
                "SELECT ip, COUNT(*) FROM attempts WHERE account=? AND ts>=? AND success=0 "
                "GROUP BY ip", (account, since),
            )
            ip_counts = [row[1] for row in cur.fetchall()]
        entropy = self._shannon_entropy(ip_counts)
        max_entropy = math.log2(len(ip_counts)) if len(ip_counts) > 1 else 0.0

        diversity_ratio = len(ips) / self.ip_diversity_threshold
        entropy_ratio = (entropy / max_entropy) if max_entropy > 0 else 0.0

        heat_score = min(100.0, heat * 20.0)              # scale EWMA heat
        diversity_score = min(100.0, diversity_ratio * 100.0)
        # high entropy (evenly spread across many IPs) + many IPs = classic slow burn
        combined = (heat_score * 0.4) + (diversity_score * 0.4) + (entropy_ratio * 100 * 0.2)

        reasons = []
        if len(ips) >= self.ip_diversity_threshold and entropy_ratio > 0.6:
            reasons.append(
                f"Account '{account}': {len(fail_ts)} failures spread evenly across "
                f"{len(ips)} distinct IPs over {self.window}s — low-and-slow pattern "
                f"(entropy {entropy:.2f}/{max_entropy:.2f})"
            )
        return min(100.0, combined), reasons
