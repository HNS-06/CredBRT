"""Device fingerprint detector — catches device spoofing and multi-account fraud.

Signals:
  - Single device used for many different accounts (farm/bot)
  - Same device appearing from different countries
  - Device fingerprint changes for same account (spoofing)
  - Known malicious device patterns
"""
import time


class DeviceFingerprintDetector:
    def __init__(self, db, cfg: dict):
        self.db = db
        self.window = cfg.get("device_window_seconds", 86400)  # 24h
        self.multi_account_threshold = cfg.get("device_multi_account_threshold", 3)
        self.multi_country_threshold = cfg.get("device_multi_country_threshold", 2)

    def score_ip(self, ip: str) -> tuple[float, list[str]]:
        since = time.time() - self.window
        devices = self.db.devices_for_ip(ip, since)

        if not devices:
            return 0.0, []

        reasons = []
        score = 0.0

        # Check if this IP uses many different device fingerprints
        if len(devices) > 2:
            score = min(100.0, len(devices) * 25.0)
            reasons.append(
                f"IP {ip} used {len(devices)} different device fingerprints "
                f"(possible device spoofing)"
            )

        # Check each device for multi-account usage
        for device_id in devices:
            accounts = self.db.accounts_for_device(device_id, since)
            if len(accounts) > self.multi_account_threshold:
                score = max(score, min(100.0, len(accounts) * 20.0))
                reasons.append(
                    f"Device {device_id[:12]}... used by {len(accounts)} accounts "
                    f"(possible bot farm)"
                )

        return score, reasons

    def score_account(self, account: str) -> tuple[float, list[str]]:
        since = time.time() - self.window

        with self.db.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT device_id, country FROM attempts "
                "WHERE account=? AND ts>=? AND device_id != ''",
                (account, since),
            )
            rows = cur.fetchall()

        if not rows:
            return 0.0, []

        devices = set(d for d, _ in rows)
        countries = set(c for d, c in rows if c and c != "??")

        reasons = []
        score = 0.0

        # Multiple devices for same account
        if len(devices) > 2:
            score = max(score, min(80.0, len(devices) * 20.0))
            reasons.append(
                f"Account '{account}' accessed from {len(devices)} different devices"
            )

        # Same device in many countries (device theft/spoofing)
        device_countries: dict[str, set] = {}
        for d, c in rows:
            if c and c != "??":
                device_countries.setdefault(d, set()).add(c)

        for device_id, country_set in device_countries.items():
            if len(country_set) > self.multi_country_threshold:
                score = max(score, min(100.0, len(country_set) * 25.0))
                reasons.append(
                    f"Device {device_id[:12]}... seen in {len(country_set)} countries: "
                    f"{', '.join(country_set)}"
                )

        return score, reasons
