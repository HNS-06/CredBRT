"""Credential_BRT color theme.

Mixed palette: Claude Code's warm coral/terracotta accent against a
dark, cool terminal-hacker backdrop (charcoal + cyan/teal), with the
usual amber/red severity ramp for alerts. The idea is "designed tool"
(coral, purposeful accents) meeting "SOC terminal" (cyan on black).
"""
from rich.theme import Theme
from rich.style import Style

# Core palette
CORAL       = "#D97757"   # Claude brand accent — primary highlight
CORAL_DIM   = "#8C5A44"
CYAN        = "#4FD1C5"   # secondary accent — terminal/hacker feel
CYAN_DIM    = "#2C7A72"
CHARCOAL    = "#1A1B1E"   # background reference (terminals rarely let us set bg)
SLATE       = "#8B92A6"   # muted text
OFFWHITE    = "#EDEDED"
AMBER       = "#E8B339"   # medium risk
ORANGE_RED  = "#E8703A"   # high risk
CRIMSON     = "#E5484D"   # critical risk
GREEN       = "#4CAF7D"   # normal / success
PURPLE      = "#9B7EDE"   # informational / secondary highlight

CREDBRT_THEME = Theme({
    "app.title": Style(color=CORAL, bold=True),
    "app.subtitle": Style(color=SLATE, italic=True),
    "app.border": Style(color=CORAL_DIM),
    "panel.header": Style(color=CYAN, bold=True),
    "text.normal": Style(color=OFFWHITE),
    "text.muted": Style(color=SLATE),
    "tier.low": Style(color=GREEN, bold=False),
    "tier.medium": Style(color=AMBER, bold=True),
    "tier.high": Style(color=ORANGE_RED, bold=True),
    "tier.critical": Style(color=CRIMSON, bold=True, blink=False),
    "value.accent": Style(color=CORAL, bold=True),
    "value.secondary": Style(color=CYAN, bold=True),
    "value.info": Style(color=PURPLE),
    "stream.success": Style(color=GREEN),
    "stream.fail": Style(color=ORANGE_RED),
    "sparkline": Style(color=CYAN),
})

TIER_STYLE = {
    "LOW": "tier.low",
    "MEDIUM": "tier.medium",
    "HIGH": "tier.high",
    "CRITICAL": "tier.critical",
}

TIER_ICON = {
    "LOW": "●",
    "MEDIUM": "▲",
    "HIGH": "◆",
    "CRITICAL": "✖",
}
