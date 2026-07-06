"""Export forensic timelines / alert history to JSON or CSV."""
import json
import csv
import time


def export_alerts_json(db, path: str):
    rows = db.recent_alerts(limit=100000)
    data = [
        {"ts": ts, "iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)),
         "entity": entity, "entity_type": entity_type, "score": score, "tier": tier, "reason": reason}
        for ts, entity, entity_type, score, tier, reason in rows
    ]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return len(data)


def export_alerts_csv(db, path: str):
    rows = db.recent_alerts(limit=100000)
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "iso_time", "entity", "entity_type", "score", "tier", "reason"])
        for ts, entity, entity_type, score, tier, reason in rows:
            iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))
            writer.writerow([ts, iso, entity, entity_type, score, tier, reason])
    return len(rows)
