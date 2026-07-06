"""Alert dispatch — persists to DB and optionally fires a webhook."""
import time
import urllib.request
import json
from credbrt.storage.models import Alert, RiskTier

TIER_ORDER = {RiskTier.LOW: 0, RiskTier.MEDIUM: 1, RiskTier.HIGH: 2, RiskTier.CRITICAL: 3}


class Notifier:
    def __init__(self, db, cfg: dict):
        self.db = db
        self.webhook_url = cfg["alerting"]["webhook_url"]
        self.min_tier = RiskTier(cfg["alerting"]["min_tier_to_alert"])
        self._seen = set()  # dedupe: (entity, tier) already alerted this run

    def maybe_alert(self, risk_score) -> bool:
        if TIER_ORDER[risk_score.tier] < TIER_ORDER[self.min_tier]:
            return False
        key = (risk_score.entity, risk_score.tier)
        if key in self._seen:
            return False
        self._seen.add(key)

        reason = "; ".join(risk_score.reasons) if risk_score.reasons else "composite score threshold exceeded"
        alert = Alert(ts=time.time(), entity=risk_score.entity, entity_type=risk_score.entity_type,
                       score=risk_score.score, tier=risk_score.tier.value, reason=reason)
        self.db.insert_alert(alert)

        if self.webhook_url:
            self._fire_webhook(alert)
        return True

    def _fire_webhook(self, alert: Alert):
        payload = json.dumps({
            "entity": alert.entity, "entity_type": alert.entity_type,
            "score": alert.score, "tier": alert.tier, "reason": alert.reason,
            "ts": alert.ts,
        }).encode()
        req = urllib.request.Request(self.webhook_url, data=payload,
                                      headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=3)
        except Exception:
            pass  # best-effort; never crash the monitor loop over a webhook failure
