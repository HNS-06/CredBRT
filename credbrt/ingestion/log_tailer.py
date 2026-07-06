"""Ingest real login-attempt logs from a JSONL file, tail -f style.

Expected line format (one JSON object per line):
    {"ts": 1720000000.0, "ip": "1.2.3.4", "account": "alice",
     "success": false, "user_agent": "curl/8.0", "country": "US", "asn": "AS123",
     "device_id": "abc123", "session_id": "sess_xyz",
     "geo_lat": 40.71, "geo_lon": -74.01,
     "response_time_ms": 150, "endpoint": "/login", "http_method": "POST",
     "failure_reason": "invalid_password"}
"""
import json
import time
from credbrt.storage.models import LoginAttempt


class LogTailer:
    def __init__(self, path: str, db):
        self.path = path
        self.db = db

    def _parse_line(self, line: str):
        obj = json.loads(line)
        return LoginAttempt(
            ts=obj.get("ts", time.time()),
            ip=obj["ip"],
            account=obj["account"],
            success=bool(obj.get("success", False)),
            user_agent=obj.get("user_agent", "unknown"),
            country=obj.get("country", "??"),
            asn=obj.get("asn", "AS0"),
            device_id=obj.get("device_id", ""),
            session_id=obj.get("session_id", ""),
            geo_lat=obj.get("geo_lat", 0.0),
            geo_lon=obj.get("geo_lon", 0.0),
            response_time_ms=obj.get("response_time_ms", 0),
            endpoint=obj.get("endpoint", "/login"),
            http_method=obj.get("http_method", "POST"),
            failure_reason=obj.get("failure_reason", ""),
        )

    def tail(self, poll_interval: float = 0.5, on_attempt=None):
        with open(self.path, "r") as f:
            f.seek(0, 2)  # jump to end — only new lines from now on
            while True:
                line = f.readline()
                if not line:
                    time.sleep(poll_interval)
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    attempt = self._parse_line(line)
                except (json.JSONDecodeError, KeyError):
                    continue
                self.db.insert_attempt(attempt)
                if on_attempt:
                    on_attempt(attempt)

    def replay(self, on_attempt=None):
        """Read the whole file from the start — useful for historical analysis."""
        with open(self.path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    attempt = self._parse_line(line)
                except (json.JSONDecodeError, KeyError):
                    continue
                self.db.insert_attempt(attempt)
                if on_attempt:
                    on_attempt(attempt)
