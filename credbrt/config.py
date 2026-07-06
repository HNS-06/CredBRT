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
        "velocity_fail_threshold": 8,          # fails/window before flag, per IP
        "account_fail_threshold": 5,           # fails/window before flag, per account
        "stuffing_ip_fanout_threshold": 4,     # 1 IP -> N distinct accounts
        "stuffing_account_fanin_threshold": 4, # 1 account targeted from N distinct IPs
        "low_and_slow_window_seconds": 3600,   # 1hr rolling window
        "low_and_slow_ewma_alpha": 0.3,
        "low_and_slow_ip_diversity_threshold": 6,
        "fingerprint_min_samples": 5,
    },
    "scoring": {
        "weight_velocity": 0.30,
        "weight_stuffing": 0.30,
        "weight_low_and_slow": 0.25,
        "weight_fingerprint": 0.15,
        "tier_medium": 30,
        "tier_high": 60,
        "tier_critical": 85,
    },
    "alerting": {
        "webhook_url": "",
        "min_tier_to_alert": "MEDIUM",
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
    # shallow-merge over defaults so partial configs still work
    merged = {**DEFAULT_CONFIG}
    for section, values in user_cfg.items():
        merged[section] = {**DEFAULT_CONFIG.get(section, {}), **values}
    return merged


def write_default_config(path: str = "config.toml"):
    with open(path, "wb") as f:
        tomli_w.dump(DEFAULT_CONFIG, f)
