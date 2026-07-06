"""Core data models for Credential_BRT."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class RiskTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class LoginAttempt:
    ts: float                     # unix timestamp
    ip: str
    account: str
    success: bool
    user_agent: str = "unknown"
    country: str = "??"
    asn: str = "AS0"
    device_id: str = ""           # device fingerprint hash
    session_id: str = ""          # session token
    geo_lat: float = 0.0         # latitude
    geo_lon: float = 0.0         # longitude
    response_time_ms: int = 0    # server response time
    endpoint: str = "/login"     # which endpoint was hit
    http_method: str = "POST"
    failure_reason: str = ""     # e.g. "invalid_password", "account_locked", "mfa_required"

    def to_row(self):
        return (self.ts, self.ip, self.account, int(self.success),
                self.user_agent, self.country, self.asn,
                self.device_id, self.session_id,
                self.geo_lat, self.geo_lon,
                self.response_time_ms, self.endpoint, self.http_method,
                self.failure_reason)


@dataclass
class RiskScore:
    entity: str                 # ip or account being scored
    entity_type: str            # "ip" | "account"
    score: float                # 0-100
    tier: RiskTier
    reasons: list = field(default_factory=list)
    ts: float = 0.0


@dataclass
class Alert:
    ts: float
    entity: str
    entity_type: str
    score: float
    tier: str
    reason: str
