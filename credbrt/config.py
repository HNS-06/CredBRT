"""Configuration loader — TOML-based, with sane security defaults."""
from pathlib import Path
import tomli
import tomli_w

DEFAULT_CONFIG = {
    "database": {
        "path": "credbrt.db",
    },
    "detection": {
        "velocity_window_seconds": 60,
        "velocity_fail_threshold": 8,
        "account_fail_threshold": 5,
        "stuffing_ip_fanout_threshold": 4,
        "stuffing_account_fanin_threshold": 4,
        "low_and_slow_window_seconds": 3600,
        "low_and_slow_ewma_alpha": 0.3,
        "low_and_slow_ip_diversity_threshold": 6,
        "fingerprint_min_samples": 5,
        # Advanced detection
        "geo_anomaly_window_seconds": 3600,
        "geo_impossible_speed_kmh": 900,
        "geo_new_country_threshold": 3,
        "session_window_seconds": 3600,
        "session_ip_change_threshold": 2,
        "session_device_change_threshold": 1,
        "device_window_seconds": 86400,
        "device_multi_account_threshold": 3,
        "device_multi_country_threshold": 2,
        "threat_intel_window_seconds": 86400,
    },
    "scoring": {
        "weight_velocity": 0.20,
        "weight_stuffing": 0.20,
        "weight_low_and_slow": 0.15,
        "weight_fingerprint": 0.15,
        "weight_device": 0.10,
        "weight_threat_intel": 0.10,
        "weight_session": 0.10,
        "weight_geo_anomaly": 0.10,
        "tier_medium": 30,
        "tier_high": 60,
        "tier_critical": 85,
    },
    "alerting": {
        "webhook_url": "",
        "min_tier_to_alert": "MEDIUM",
    },
    "threat_intel": {
        "enabled": True,
        "auto_block_threshold": 80,
        "load_defaults": True,
    },
    "live_traffic": {
        "enabled": False,
        "rate_per_second": 2.0,
    },
    "ui": {
        "refresh_hz": 4,
    },
}


def load_config(path: str = "config.toml") -> dict:
    p = Path(path)
    if not p.exists():
        return DEFAULT_CONFIG
    with open(p, "rb") as f:
        user_cfg = tomli.load(f)
    # Deep merge over defaults
    merged = {**DEFAULT_CONFIG}
    for section, values in user_cfg.items():
        if isinstance(values, dict) and section in merged:
            merged[section] = {**merged[section], **values}
        else:
            merged[section] = values
    return merged


def write_default_config(path: str = "config.toml"):
    with open(path, "wb") as f:
        tomli_w.dump(DEFAULT_CONFIG, f)
