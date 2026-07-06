"""Small reusable rendering helpers for the dashboard."""
from rich.text import Text

SPARK_CHARS = "▁▂▃▄▅▆▇█"


def sparkline(values: list[float], width: int = 30) -> Text:
    if not values:
        return Text("·" * width, style="text.muted")
    values = values[-width:]
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1
    chars = []
    for v in values:
        idx = int(((v - lo) / span) * (len(SPARK_CHARS) - 1))
        chars.append(SPARK_CHARS[idx])
    pad = width - len(chars)
    return Text("·" * pad + "".join(chars), style="sparkline")


def risk_gauge(score: float, width: int = 24) -> Text:
    filled = int((score / 100) * width)
    filled = max(0, min(width, filled))
    if score >= 85:
        style = "tier.critical"
    elif score >= 60:
        style = "tier.high"
    elif score >= 30:
        style = "tier.medium"
    else:
        style = "tier.low"
    bar = Text()
    bar.append("█" * filled, style=style)
    bar.append("░" * (width - filled), style="text.muted")
    bar.append(f"  {score:5.1f}", style=style)
    return bar
