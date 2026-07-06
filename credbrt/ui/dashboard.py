"""Live terminal dashboard for Credential_BRT.

Enhanced with real-time stats, geo info, device tracking, and threat intel status.
"""
import time
from collections import deque, defaultdict

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich.align import Align

from credbrt.ui.theme import CREDBRT_THEME, TIER_STYLE, TIER_ICON
from credbrt.ui.widgets import sparkline, risk_gauge

console = Console(theme=CREDBRT_THEME)


class Dashboard:
    def __init__(self, db, risk_engine, notifier, cfg: dict):
        self.db = db
        self.risk_engine = risk_engine
        self.notifier = notifier
        self.cfg = cfg
        self.attempt_history = deque(maxlen=120)
        self.recent_stream = deque(maxlen=12)
        self._stats = {
            "total_attempts": 0,
            "total_failed": 0,
            "total_success": 0,
            "unique_ips": set(),
            "unique_accounts": set(),
            "threat_ips": 0,
            "alerts_fired": 0,
            "countries_seen": set(),
        }

    def _pull_new_attempts(self):
        rows = self.db.recent_attempts(seconds=15, limit=200)
        for ts, ip, account, success, ua, country, asn in rows:
            self.recent_stream.appendleft((ts, ip, account, bool(success), country))
            self._stats["total_attempts"] += 1
            if success:
                self._stats["total_success"] += 1
            else:
                self._stats["total_failed"] += 1
            self._stats["unique_ips"].add(ip)
            self._stats["unique_accounts"].add(account)
            if country and country != "??":
                self._stats["countries_seen"].add(country)
        return len(rows)

    def _get_threat_count(self):
        """Count IPs flagged by threat intel."""
        with self.db.cursor() as cur:
            cur.execute("SELECT COUNT(DISTINCT ip) FROM threat_intel")
            return cur.fetchone()[0]

    def _get_alert_stats(self):
        """Get alert statistics."""
        with self.db.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM alerts")
            total = cur.fetchone()[0]
            cur.execute("SELECT tier, COUNT(*) FROM alerts GROUP BY tier")
            by_tier = dict(cur.fetchall())
        return total, by_tier

    def _top_offenders(self, limit=8):
        since = time.time() - self.cfg["detection"]["low_and_slow_window_seconds"]
        with self.db.cursor() as cur:
            cur.execute(
                "SELECT ip, COUNT(*) as c FROM attempts WHERE ts>=? AND success=0 "
                "GROUP BY ip ORDER BY c DESC LIMIT ?", (since, limit),
            )
            ips = [r[0] for r in cur.fetchall()]
            cur.execute(
                "SELECT account, COUNT(*) as c FROM attempts WHERE ts>=? AND success=0 "
                "GROUP BY account ORDER BY c DESC LIMIT ?", (since, limit),
            )
            accounts = [r[0] for r in cur.fetchall()]
        scores = [self.risk_engine.score_ip(ip) for ip in ips]
        acct_scores = [self.risk_engine.score_account(a) for a in accounts]
        for rs in scores + acct_scores:
            self.notifier.maybe_alert(rs)
        return scores, acct_scores

    def _render_header(self):
        title = Text("CREDENTIAL_BRT", style="app.title")
        subtitle = Text("  brute-force & credential-stuffing detection engine", style="app.subtitle")
        clock = Text(time.strftime(" %Y-%m-%d %H:%M:%S "), style="value.secondary")
        row = Table.grid(expand=True)
        row.add_column(justify="left", ratio=1)
        row.add_column(justify="right")
        row.add_row(Text.assemble(title, subtitle), clock)
        return Panel(row, style="app.border", padding=(0, 1))

    def _render_stats(self):
        """Real-time statistics panel."""
        table = Table.grid(padding=(0, 2), expand=True)
        table.add_column(width=14)
        table.add_column(width=10)
        table.add_column(width=14)
        table.add_column(width=10)

        stats = self._stats
        total = stats["total_attempts"]
        failed = stats["total_failed"]
        success_rate = f"{(stats['total_success']/total*100):.1f}%" if total > 0 else "—"

        table.add_row(
            Text(f"Total: {total}", style="value.accent"),
            Text(f"Failed: {failed}", style="stream.fail"),
            Text(f"Success: {success_rate}", style="stream.success"),
            Text(f"IPs: {len(stats['unique_ips'])}", style="value.info"),
        )
        return Panel(table, title="[panel.header]real-time stats[/]", border_style="app.border")

    def _render_stream(self):
        table = Table.grid(padding=(0, 1), expand=True)
        table.add_column(width=9)
        table.add_column(width=16)
        table.add_column(width=14)
        table.add_column(width=8)
        table.add_column()
        for item in list(self.recent_stream)[:10]:
            ts, ip, account, success, country = item if len(item) == 5 else (*item, "??")
            tstr = time.strftime("%H:%M:%S", time.localtime(ts))
            status = Text("OK", style="stream.success") if success else Text("FAIL", style="stream.fail")
            table.add_row(
                Text(tstr, style="text.muted"),
                Text(ip, style="text.normal"),
                Text(account, style="value.info"),
                Text(country, style="value.secondary"),
                status,
            )
        if not self.recent_stream:
            table.add_row(Text("waiting for attempts…", style="text.muted"))
        return Panel(table, title="[panel.header]live attempt stream[/]", border_style="app.border")

    def _render_activity(self):
        n = self._pull_new_attempts()
        self.attempt_history.append(n)
        spark = sparkline(list(self.attempt_history), width=40)
        body = Table.grid()
        body.add_row(Text("attempts / 15s window", style="text.muted"))
        body.add_row(spark)
        body.add_row(Text(f"  current: {n}", style="value.accent"))
        return Panel(body, title="[panel.header]activity[/]", border_style="app.border")

    def _render_offenders(self, ip_scores, acct_scores):
        table = Table(expand=True, show_edge=False, header_style="panel.header")
        table.add_column("Entity", ratio=2)
        table.add_column("Type", width=8)
        table.add_column("Risk", ratio=3)
        table.add_column("Tier", width=10)

        combined = sorted(ip_scores + acct_scores, key=lambda r: r.score, reverse=True)[:10]
        for rs in combined:
            tier_style = TIER_STYLE[rs.tier.value]
            icon = TIER_ICON[rs.tier.value]
            table.add_row(
                Text(rs.entity, style="text.normal"),
                Text(rs.entity_type, style="text.muted"),
                risk_gauge(rs.score),
                Text(f"{icon} {rs.tier.value}", style=tier_style),
            )
        if not combined:
            table.add_row("—", "—", risk_gauge(0), "—")
        return Panel(table, title="[panel.header]top offenders — risk ranking[/]", border_style="app.border")

    def _render_alerts(self):
        rows = self.db.recent_alerts(limit=8)
        table = Table.grid(padding=(0, 1), expand=True)
        table.add_column(width=9)
        table.add_column(width=12)
        table.add_column(width=10)
        table.add_column()
        for ts, entity, entity_type, score, tier, reason in rows:
            tstr = time.strftime("%H:%M:%S", time.localtime(ts))
            tier_style = TIER_STYLE.get(tier, "text.normal")
            table.add_row(
                Text(tstr, style="text.muted"),
                Text(entity, style="value.accent"),
                Text(tier, style=tier_style),
                Text(reason[:65], style="text.muted"),
            )
        if not rows:
            table.add_row(Text("no alerts yet", style="text.muted"))
        return Panel(table, title="[panel.header]recent alerts[/]", border_style="app.border")

    def _render_threat_summary(self):
        """Threat intelligence summary panel."""
        threat_count = self._get_threat_count()
        alert_total, alert_by_tier = self._get_alert_stats()

        table = Table.grid(padding=(0, 2), expand=True)
        table.add_column(width=20)
        table.add_column()

        table.add_row(
            Text("Threat IPs:", style="text.muted"),
            Text(str(threat_count), style="value.accent"),
        )

        # Alert breakdown by tier
        tier_parts = []
        for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = alert_by_tier.get(tier, 0)
            if count > 0:
                style = TIER_STYLE.get(tier, "text.normal")
                tier_parts.append(Text(f"{tier}:{count} ", style=style))

        table.add_row(
            Text("Alerts:", style="text.muted"),
            Text.assemble(*tier_parts) if tier_parts else Text("0", style="text.muted"),
        )

        countries = self._stats["countries_seen"]
        table.add_row(
            Text("Countries:", style="text.muted"),
            Text(str(len(countries)) if countries else "0", style="value.info"),
        )

        return Panel(table, title="[panel.header]threat summary[/]", border_style="app.border")

    def _render_footer(self):
        text = Text(
            "q quit  |  live: credbrt live --rate 5  |  simulate: credbrt simulate full  |  threats: credbrt threats --load-defaults",
            style="text.muted"
        )
        return Panel(Align.center(text), border_style="app.border")

    def render(self) -> Layout:
        ip_scores, acct_scores = self._top_offenders()

        layout = Layout()
        layout.split_column(
            Layout(self._render_header(), size=3),
            Layout(name="body"),
            Layout(self._render_footer(), size=3),
        )
        layout["body"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=3),
        )
        layout["left"].split_column(
            Layout(self._render_stats(), size=5),
            Layout(self._render_activity(), size=8),
            Layout(self._render_stream()),
        )
        layout["right"].split_column(
            Layout(self._render_offenders(ip_scores, acct_scores), ratio=2),
            Layout(self._render_alerts(), ratio=1),
        )
        return layout

    def run(self, refresh_hz: int = 4):
        with Live(self.render(), console=console, refresh_per_second=refresh_hz, screen=True) as live:
            try:
                while True:
                    time.sleep(1.0 / refresh_hz)
                    live.update(self.render())
            except KeyboardInterrupt:
                pass
