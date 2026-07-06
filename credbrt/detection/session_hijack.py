"""Session hijacking detector — catches stolen/leaked session tokens.

Signals:
  - Same session token used from different IPs or device fingerprints
  - Session used after account was accessed from a different location
  - Session activity from known-malicious IPs
"""
import time


class SessionHijackDetector:
    def __init__(self, db, cfg: dict):
        self.db = db
        self.window = cfg.get("session_window_seconds", 3600)
        self.ip_change_threshold = cfg.get("session_ip_change_threshold", 2)
        self.device_change_threshold = cfg.get("session_device_change_threshold", 1)

    def score_account(self, account: str) -> tuple[float, list[str]]:
        since = time.time() - self.window

        with self.db.cursor() as cur:
            cur.execute(
                "SELECT ts, ip, device_id, session_id, country, endpoint "
                "FROM attempts WHERE account=? AND ts>=? AND session_id != '' "
                "ORDER BY ts",
                (account, since),
            )
            sessions = cur.fetchall()

        if len(sessions) < 2:
            return 0.0, []

        reasons = []
        score = 0.0

        # Group by session_id
        by_session: dict[str, list] = {}
        for ts, ip, device_id, session_id, country, endpoint in sessions:
            by_session.setdefault(session_id, []).append((ts, ip, device_id, country, endpoint))

        for session_id, events in by_session.items():
            if len(events) < 2:
                continue

            ips = set(ip for _, ip, _, _, _ in events)
            devices = set(d for _, _, d, _, _ in events if d)
            countries = set(c for _, _, _, c, _ in events)

            # Check for IP changes within same session
            if len(ips) > self.ip_change_threshold:
                score = max(score, min(100.0, 50.0 + len(ips) * 15.0))
                reasons.append(
                    f"Session {session_id[:8]}... used from {len(ips)} different IPs: "
                    f"{', '.join(list(ips)[:3])}"
                )

            # Check for device changes
            if len(devices) > self.device_change_threshold:
                score = max(score, min(100.0, 60.0 + len(devices) * 10.0))
                reasons.append(
                    f"Session {session_id[:8]}... used from {len(devices)} different devices"
                )

            # Check for country changes within session
            if len(countries) > 1:
                score = max(score, 70.0)
                reasons.append(
                    f"Session {session_id[:8]}... active in {len(countries)} countries: "
                    f"{', '.join(countries)}"
                )

            # Check for suspicious endpoint access patterns
            admin_endpoints = [e for _, _, _, _, e in events if 'admin' in e.lower()]
            if admin_endpoints:
                score = max(score, 60.0)
                reasons.append(
                    f"Session {session_id[:8]}... accessed {len(admin_endpoints)} admin endpoints"
                )

        return score, reasons

    def score_ip(self, ip: str) -> tuple[float, list[str]]:
        """Check if an IP is being used for session hijacking attempts."""
        since = time.time() - self.window

        with self.db.cursor() as cur:
            cur.execute(
                "SELECT account, session_id, device_id FROM attempts "
                "WHERE ip=? AND ts>=? AND session_id != ''",
                (ip, since),
            )
            rows = cur.fetchall()

        if len(rows) < 3:
            return 0.0, []

        # Check how many different accounts this IP uses sessions for
        accounts = set(a for a, _, _ in rows)
        sessions = set(s for _, s, _ in rows)
        devices = set(d for _, _, d in rows if d)

        reasons = []
        score = 0.0

        if len(accounts) > 2:
            score = max(score, min(100.0, len(accounts) * 25.0))
            reasons.append(
                f"IP {ip} used sessions for {len(accounts)} different accounts"
            )

        if len(sessions) > 3:
            score = max(score, min(80.0, len(sessions) * 15.0))
            reasons.append(
                f"IP {ip} used {len(sessions)} different session tokens"
            )

        return score, reasons
