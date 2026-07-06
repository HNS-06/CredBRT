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

    def to_row(self):
        return (self.ts, self.ip, self.account, int(self.success),
                self.user_agent, self.country, self.asn)


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
