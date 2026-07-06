"""Credential_BRT — terminal CLI entrypoint.

    credbrt init                 create config.toml + fresh db
    credbrt monitor              launch the live risk dashboard
    credbrt simulate <pattern>   inject synthetic traffic for testing
    credbrt live                 start live traffic generation + monitor
    credbrt ingest <file.jsonl>  tail a real auth-log file live
    credbrt replay <file.jsonl>  bulk-load historical logs
    credbrt report --format csv  export alert history
    credbrt threats              manage threat intelligence
    credbrt reset                wipe the database
"""
import sys
import click
from rich.console import Console

from credbrt.config import load_config, write_default_config
from credbrt.storage.db import Database
from credbrt.scoring.risk_engine import RiskEngine
from credbrt.alerting.notifier import Notifier
from credbrt.ingestion.simulator import Simulator
from credbrt.ingestion.log_tailer import LogTailer
from credbrt.ingestion.live_generator import LiveTrafficGenerator
from credbrt.ui.dashboard import Dashboard
from credbrt.ui.theme import CREDBRT_THEME
from credbrt.reporting import export as export_mod

console = Console(theme=CREDBRT_THEME)

_live_generator: LiveTrafficGenerator = None


def _bootstrap(config_path="config.toml"):
    cfg = load_config(config_path)
    db = Database(cfg["database"]["path"])
    engine = RiskEngine(db, cfg)
    notifier = Notifier(db, cfg)
    return cfg, db, engine, notifier


@click.group()
def main():
    """Credential_BRT — brute-force & credential-stuffing detection, in your terminal."""
    pass


@main.command()
def init():
    """Create a default config.toml in the current directory."""
    write_default_config("config.toml")
    console.print("[value.accent]✓[/] created config.toml")
    Database("credbrt.db")
    console.print("[value.accent]✓[/] initialized credbrt.db")
    console.print("\nRun [value.secondary]credbrt simulate demo[/] then [value.secondary]credbrt monitor[/] to see it live.")


@main.command()
def monitor():
    """Launch the live terminal dashboard."""
    cfg, db, engine, notifier = _bootstrap()

    # Load threat intel if enabled
    if cfg.get("threat_intel", {}).get("load_defaults", True):
        from credbrt.detection.threat_intel import ThreatIntelDetector
        ti = ThreatIntelDetector(db, cfg["detection"])
        ti.load_default_threats()
        console.print("[value.accent]✓[/] loaded threat intelligence")

    dash = Dashboard(db, engine, notifier, cfg)
    console.print("[app.title]Starting Credential_BRT monitor…[/] (Ctrl+C to quit)")
    dash.run(refresh_hz=cfg["ui"]["refresh_hz"])


@main.command()
@click.option("--rate", default=2.0, help="Traffic generation rate (attempts/second)")
def live(rate):
    """Start live traffic generation and launch dashboard."""
    global _live_generator
    cfg, db, engine, notifier = _bootstrap()

    # Load threat intel
    if cfg.get("threat_intel", {}).get("load_defaults", True):
        from credbrt.detection.threat_intel import ThreatIntelDetector
        ti = ThreatIntelDetector(db, cfg["detection"])
        ti.load_default_threats()

    # Start live generator
    _live_generator = LiveTrafficGenerator(db, rate_per_second=rate)
    _live_generator.start()
    console.print(f"[value.accent]✓[/] live traffic generator started ({rate} attempts/sec)")

    dash = Dashboard(db, engine, notifier, cfg)
    console.print("[app.title]Starting live monitor…[/] (Ctrl+C to quit)")
    try:
        dash.run(refresh_hz=cfg["ui"]["refresh_hz"])
    finally:
        _live_generator.stop()


@main.command()
@click.argument("pattern", default="demo",
                 type=click.Choice(["demo", "normal", "bruteforce", "spray", "lowandslow",
                                     "geo", "session", "full"]))
def simulate(pattern):
    """Inject synthetic traffic patterns into the local DB to test detectors."""
    cfg, db, engine, notifier = _bootstrap()
    sim = Simulator(db)

    if pattern == "demo":
        sim.run_all_demo_patterns()
        console.print("[value.accent]✓[/] injected full demo pattern set (all attack types)")
    elif pattern == "normal":
        sim.normal_traffic(100)
        console.print("[value.accent]✓[/] injected realistic baseline traffic")
    elif pattern == "bruteforce":
        sim.brute_force(25)
        console.print("[value.accent]✓[/] injected brute-force pattern")
    elif pattern == "spray":
        sim.password_spray(15)
        console.print("[value.accent]✓[/] injected password-spray pattern")
    elif pattern == "lowandslow":
        sim.credential_stuffing_low_and_slow(n_ips=18)
        console.print("[value.accent]✓[/] injected low-and-slow distributed stuffing pattern")
    elif pattern == "geo":
        sim.geo_anomaly_pattern()
        console.print("[value.accent]✓[/] injected geo-anomaly (impossible travel) pattern")
    elif pattern == "session":
        sim.session_hijacking_pattern()
        console.print("[value.accent]✓[/] injected session hijacking pattern")
    elif pattern == "full":
        sim.run_all_demo_patterns()
        sim.geo_anomaly_pattern()
        sim.session_hijacking_pattern()
        console.print("[value.accent]✓[/] injected ALL patterns (comprehensive demo)")

    console.print("Run [value.secondary]credbrt monitor[/] to see the risk scores.")


@main.command()
@click.argument("filepath")
def ingest(filepath):
    """Tail a JSONL auth-log file live and score attempts as they arrive."""
    cfg, db, engine, notifier = _bootstrap()
    tailer = LogTailer(filepath, db)
    console.print(f"[app.title]Tailing[/] {filepath} — run [value.secondary]credbrt monitor[/] in another terminal.")
    try:
        tailer.tail()
    except KeyboardInterrupt:
        console.print("\nstopped.")


@main.command()
@click.argument("filepath")
def replay(filepath):
    """Bulk-load a historical JSONL log file for retrospective analysis."""
    cfg, db, engine, notifier = _bootstrap()
    tailer = LogTailer(filepath, db)
    count = 0

    def _count(_):
        nonlocal count
        count += 1

    tailer.replay(on_attempt=_count)
    console.print(f"[value.accent]✓[/] replayed {count} attempts from {filepath}")


@main.command()
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "csv"]))
@click.option("--out", default=None, help="output file path")
def report(fmt, out):
    """Export alert history to JSON or CSV."""
    cfg, db, engine, notifier = _bootstrap()
    out = out or f"credbrt_report.{fmt}"
    if fmt == "json":
        n = export_mod.export_alerts_json(db, out)
    else:
        n = export_mod.export_alerts_csv(db, out)
    console.print(f"[value.accent]✓[/] exported {n} alerts to {out}")


@main.command()
@click.option("--load-defaults", is_flag=True, help="Load built-in threat intelligence")
@click.option("--add", nargs=3, type=str, help="Add threat: --add <ip> <source> <threat_type>")
@click.option("--list", "list_threats", is_flag=True, help="List known threats")
def threats(load_defaults, add, list_threats):
    """Manage threat intelligence database."""
    cfg, db, engine, notifier = _bootstrap()

    if load_defaults:
        from credbrt.detection.threat_intel import ThreatIntelDetector
        ti = ThreatIntelDetector(db, cfg["detection"])
        ti.load_default_threats()
        console.print("[value.accent]✓[/] loaded default threat intelligence")

    if add:
        ip, source, threat_type = add
        db.insert_threat_intel(ip, source, threat_type, 0.8)
        console.print(f"[value.accent]✓[/] added {ip} as {threat_type} from {source}")

    if list_threats:
        with db.cursor() as cur:
            cur.execute("SELECT ip, source, threat_type, confidence FROM threat_intel LIMIT 50")
            rows = cur.fetchall()
        if rows:
            console.print(f"[value.accent]Known threats:[/]")
            for ip, source, ttype, conf in rows:
                console.print(f"  {ip}  {source}  {ttype}  (confidence: {conf:.0%})")
        else:
            console.print("[text.muted]No threats in database. Run with --load-defaults to populate.[/]")


@main.command()
def reset():
    """Wipe all stored attempts and alerts."""
    cfg, db, engine, notifier = _bootstrap()
    if click.confirm("This will delete all stored attempts and alerts. Continue?"):
        db.wipe()
        console.print("[value.accent]✓[/] database wiped.")


if __name__ == "__main__":
    main()
