"""Ingest real login-attempt logs from a JSONL file, tail -f style.

Expected line format (one JSON object per line):
    {"ts": 1720000000.0, "ip": "1.2.3.4", "account": "alice",
     "success": false, "user_agent": "curl/8.0", "country": "US", "asn": "AS123"}

Any auth system (nginx/Apache access log post-processor, app server
middleware, cloud IdP export) can be adapted to emit this shape.
"""
import json
import time
from credbrt.storage.models import LoginAttempt


class LogTailer:
    def __init__(self, path: str, db):
        self.path = path
        self.db = db

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
                    obj = json.loads(line)
                    attempt = LoginAttempt(
                        ts=obj.get("ts", time.time()),
                        ip=obj["ip"],
                        account=obj["account"],
                        success=bool(obj.get("success", False)),
                        user_agent=obj.get("user_agent", "unknown"),
                        country=obj.get("country", "??"),
                        asn=obj.get("asn", "AS0"),
                    )
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
                    obj = json.loads(line)
                    attempt = LoginAttempt(
                        ts=obj.get("ts", time.time()),
                        ip=obj["ip"],
                        account=obj["account"],
                        success=bool(obj.get("success", False)),
                        user_agent=obj.get("user_agent", "unknown"),
                        country=obj.get("country", "??"),
                        asn=obj.get("asn", "AS0"),
                    )
                except (json.JSONDecodeError, KeyError):
                    continue
                self.db.insert_attempt(attempt)
                if on_attempt:
                    on_attempt(attempt)
