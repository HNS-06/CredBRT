"""Composite risk engine — fuses all detector sub-scores into one
0-100 risk score per entity (IP or account) with a tier classification.
"""
import time
from credbrt.storage.models import RiskScore, RiskTier
from credbrt.detection.velocity import VelocityDetector
from credbrt.detection.credential_stuffing import CredentialStuffingDetector
from credbrt.detection.low_and_slow import LowAndSlowDetector
from credbrt.detection.fingerprint import FingerprintDetector


class RiskEngine:
    def __init__(self, db, cfg: dict):
        self.db = db
        self.cfg = cfg
        d = cfg["detection"]
        s = cfg["scoring"]
        self.velocity = VelocityDetector(db, d)
        self.stuffing = CredentialStuffingDetector(db, d)
        self.low_slow = LowAndSlowDetector(db, d)
        self.fingerprint = FingerprintDetector(db, d)
        self.weights = s

    def _tier(self, score: float) -> RiskTier:
        s = self.weights
        if score >= s["tier_critical"]:
            return RiskTier.CRITICAL
        if score >= s["tier_high"]:
            return RiskTier.HIGH
        if score >= s["tier_medium"]:
            return RiskTier.MEDIUM
        return RiskTier.LOW

    def score_ip(self, ip: str) -> RiskScore:
        v_score, v_reasons = self.velocity.score_ip(ip)
        st_score, st_reasons = self.stuffing.score_ip_fanout(ip)
        fp_score, fp_reasons = self.fingerprint.score_ip(ip)

        composite = (
            v_score * self.weights["weight_velocity"]
            + st_score * self.weights["weight_stuffing"]
            + fp_score * self.weights["weight_fingerprint"]
        ) / (self.weights["weight_velocity"] + self.weights["weight_stuffing"] + self.weights["weight_fingerprint"])

        reasons = v_reasons + st_reasons + fp_reasons
        return RiskScore(entity=ip, entity_type="ip", score=round(composite, 1),
                          tier=self._tier(composite), reasons=reasons, ts=time.time())

    def score_account(self, account: str) -> RiskScore:
        v_score, v_reasons = self.velocity.score_account(account)
        st_score, st_reasons = self.stuffing.score_account_fanin(account)
        ls_score, ls_reasons = self.low_slow.score_account(account)

        composite = (
            v_score * self.weights["weight_velocity"]
            + st_score * self.weights["weight_stuffing"]
            + ls_score * self.weights["weight_low_and_slow"]
        ) / (self.weights["weight_velocity"] + self.weights["weight_stuffing"] + self.weights["weight_low_and_slow"])

        reasons = v_reasons + st_reasons + ls_reasons
        return RiskScore(entity=account, entity_type="account", score=round(composite, 1),
                          tier=self._tier(composite), reasons=reasons, ts=time.time())
