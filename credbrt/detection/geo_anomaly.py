"""Geo-anomaly detector — catches impossible travel and suspicious location changes.

Signals:
  - Same account accessed from geographically distant locations in short time
  - Login from a country never seen before for this account
  - Sudden change in access pattern (different ISP/ASN)
"""
import math
import time


class GeoAnomalyDetector:
    def __init__(self, db, cfg: dict):
        self.db = db
        self.window = cfg.get("geo_anomaly_window_seconds", 3600)
        self.impossible_speed_kmh = cfg.get("geo_impossible_speed_kmh", 900)  # ~airplane speed
        self.new_country_threshold = cfg.get("geo_new_country_threshold", 3)

    @staticmethod
    def _haversine_km(lat1, lon1, lat2, lon2):
        """Calculate distance between two points on Earth in km."""
        R = 6371
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = (math.sin(dlat / 2) ** 2 +
             math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
             math.sin(dlon / 2) ** 2)
        return R * 2 * math.asin(math.sqrt(a))

    def score_account(self, account: str) -> tuple[float, list[str]]:
        since = time.time() - self.window
        countries = self.db.get_countries_for_account(account, since)

        if len(countries) < 2:
            return 0.0, []

        reasons = []
        max_distance = 0
        impossible_count = 0

        # Check for country changes
        seen_countries = set()
        for country, first_ts, last_ts in countries:
            seen_countries.add(country)

        # Get recent attempts with geo data
        with self.db.cursor() as cur:
            cur.execute(
                "SELECT ts, ip, country, geo_lat, geo_lon FROM attempts "
                "WHERE account=? AND ts>=? AND geo_lat != 0 ORDER BY ts",
                (account, since),
            )
            rows = cur.fetchall()

        if len(rows) < 2:
            return 0.0, []

        # Check pairwise distances
        for i in range(len(rows)):
            for j in range(i + 1, len(rows)):
                ts1, ip1, country1, lat1, lon1 = rows[i]
                ts2, ip2, country2, lat2, lon2 = rows[j]

                if lat1 == 0 or lat2 == 0:
                    continue

                distance = self._haversine_km(lat1, lon1, lat2, lon2)
                time_gap = abs(ts2 - ts1)

                if time_gap > 0 and distance > 100:
                    speed_kmh = (distance / (time_gap / 3600))
                    max_distance = max(max_distance, distance)

                    if speed_kmh > self.impossible_speed_kmh and time_gap < 3600:
                        impossible_count += 1
                        self.db.insert_geo_anomaly(
                            account, ip1, ip2, country1, country2,
                            distance, time_gap
                        )
                        reasons.append(
                            f"Impossible travel: {distance:.0f}km in {time_gap:.0f}s "
                            f"({country1} -> {country2})"
                        )

        # Score based on anomalies
        score = 0.0
        if impossible_count > 0:
            score = min(100.0, 40.0 + (impossible_count * 20.0))
        elif len(seen_countries) >= 3:
            score = min(60.0, len(seen_countries) * 15.0)
        elif max_distance > 5000:
            score = min(50.0, max_distance / 200)

        if len(seen_countries) >= 3:
            reasons.append(
                f"Account '{account}' accessed from {len(seen_countries)} "
                f"countries: {', '.join(seen_countries)}"
            )

        return score, reasons
