"""Composite risk engine — fuses all detector sub-scores into one
0-100 risk score per entity (IP or account) with a tier classification.
"""
import time
from credbrt.storage.models import RiskScore, RiskTier
from credbrt.detection.velocity import VelocityDetector
from credbrt.detection.credential_stuffing import CredentialStuffingDetector
from credbrt.detection.low_and_slow import LowAndSlowDetector
from credbrt.detection.fingerprint import FingerprintDetector
from credbrt.detection.geo_anomaly import GeoAnomalyDetector
from credbrt.detection.session_hijack import SessionHijackDetector
from credbrt.detection.device_fingerprint import DeviceFingerprintDetector
from credbrt.detection.threat_intel import ThreatIntelDetector


class RiskEngine:
    def __init__(self, db, cfg: dict):
        self.db = db
        self.cfg = cfg
        d = cfg["detection"]
        s = cfg["scoring"]

        # Core detectors
        self.velocity = VelocityDetector(db, d)
        self.stuffing = CredentialStuffingDetector(db, d)
        self.low_slow = LowAndSlowDetector(db, d)
        self.fingerprint = FingerprintDetector(db, d)

        # Advanced detectors
        self.geo_anomaly = GeoAnomalyDetector(db, d)
        self.session_hijack = SessionHijackDetector(db, d)
        self.device_fp = DeviceFingerprintDetector(db, d)
        self.threat_intel = ThreatIntelDetector(db, d)

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

    def _weighted_average(self, scores: list[tuple[float, float]]) -> float:
        """Calculate weighted average from list of (score, weight) tuples."""
        total_weight = sum(w for _, w in scores)
        if total_weight == 0:
            return 0.0
        return sum(s * w for s, w in scores) / total_weight

    def score_ip(self, ip: str) -> RiskScore:
        # Core detectors
        v_score, v_reasons = self.velocity.score_ip(ip)
        st_score, st_reasons = self.stuffing.score_ip_fanout(ip)
        fp_score, fp_reasons = self.fingerprint.score_ip(ip)

        # Advanced detectors
        di_score, di_reasons = self.device_fp.score_ip(ip)
        ti_score, ti_reasons = self.threat_intel.score_ip(ip)
        sj_score, sj_reasons = self.session_hijack.score_ip(ip)

        # Weighted composite
        w = self.weights
        composite = self._weighted_average([
            (v_score, w.get("weight_velocity", 0.20)),
            (st_score, w.get("weight_stuffing", 0.20)),
            (fp_score, w.get("weight_fingerprint", 0.15)),
            (di_score, w.get("weight_device", 0.15)),
            (ti_score, w.get("weight_threat_intel", 0.15)),
            (sj_score, w.get("weight_session", 0.15)),
        ])

        reasons = v_reasons + st_reasons + fp_reasons + di_reasons + ti_reasons + sj_reasons
        return RiskScore(entity=ip, entity_type="ip", score=round(composite, 1),
                          tier=self._tier(composite), reasons=reasons, ts=time.time())

    def score_account(self, account: str) -> RiskScore:
        # Core detectors
        v_score, v_reasons = self.velocity.score_account(account)
        st_score, st_reasons = self.stuffing.score_account_fanin(account)
        ls_score, ls_reasons = self.low_slow.score_account(account)

        # Advanced detectors
        ga_score, ga_reasons = self.geo_anomaly.score_account(account)
        sj_score, sj_reasons = self.session_hijack.score_account(account)
        di_score, di_reasons = self.device_fp.score_account(account)
        ti_score, ti_reasons = self.threat_intel.score_account(account)

        # Weighted composite
        w = self.weights
        composite = self._weighted_average([
            (v_score, w.get("weight_velocity", 0.15)),
            (st_score, w.get("weight_stuffing", 0.15)),
            (ls_score, w.get("weight_low_and_slow", 0.15)),
            (ga_score, w.get("weight_geo_anomaly", 0.15)),
            (sj_score, w.get("weight_session", 0.15)),
            (di_score, w.get("weight_device", 0.10)),
            (ti_score, w.get("weight_threat_intel", 0.15)),
        ])

        reasons = v_reasons + st_reasons + ls_reasons + ga_reasons + sj_reasons + di_reasons + ti_reasons
        return RiskScore(entity=account, entity_type="account", score=round(composite, 1),
                          tier=self._tier(composite), reasons=reasons, ts=time.time())
