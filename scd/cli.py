"""Command-line interface for Suspicious Connection Detector."""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime

from . import __version__
from .detector import (
    DEFAULT_SUSPICIOUS_PORTS,
    Config,
    Deduper,
    Detector,
    collect_connections,
    parse_networks,
    write_jsonl,
)
from .enrich import CachedEnricher, build_provider

SEVERITY_STYLE = {"high": "bold red", "medium": "yellow", "low": "cyan",
                  "info": "", "allowlisted": "dim"}


def csv_list(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def port_list(value: str) -> frozenset:
    try:
        return frozenset(int(p) for p in csv_list(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid port list: {value}") from exc


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scd",
        description="Monitor live network connections and flag suspicious ones.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-t", "--trusted-countries", type=csv_list, default=["IN"],
                   help="comma-separated ISO country codes treated as normal (default: IN)")
    p.add_argument("-i", "--interval", type=float, default=5.0,
                   help="seconds between scans (default: 5)")
    p.add_argument("--once", action="store_true", help="scan one time and exit")
    p.add_argument("--provider", choices=["ipapi", "geolite2", "none"], default="none",
                   help="country lookup: none (default, nothing leaves the host), "
                        "geolite2 (offline DB) or ipapi (online, sends public IPs to ipapi.co)")
    p.add_argument("--geoip-db", help="path to GeoLite2-Country.mmdb (for --provider geolite2)")
    p.add_argument("--cache-ttl", type=float, default=3600,
                   help="seconds to cache a successful lookup (default: 3600)")
    p.add_argument("--timeout", type=float, default=3.0, help="lookup timeout in seconds")
    p.add_argument("--allow-process", type=csv_list, default=[],
                   help="comma-separated process names never to alert on (e.g. chrome.exe,svchost.exe)")
    p.add_argument("--allow-ip", type=csv_list, default=[],
                   help="comma-separated IPs/CIDRs never to alert on")
    p.add_argument("--suspicious-ports", type=port_list, default=DEFAULT_SUSPICIOUS_PORTS,
                   help="comma-separated remote ports that raise an alert")
    p.add_argument("--alert-on-unknown", action="store_true",
                   help="also alert when the country lookup fails")
    p.add_argument("--dedupe-window", type=float, default=600,
                   help="seconds before the same alert is logged again (default: 600)")
    p.add_argument("-o", "--log", default="suspicious_connections.jsonl",
                   help="JSON Lines alert log (default: suspicious_connections.jsonl)")
    p.add_argument("--alerts-only", action="store_true",
                   help="only show connections that raised an alert")
    p.add_argument("--json", action="store_true",
                   help="print new alerts as JSON lines to stdout instead of a table")
    return p


def config_from_args(args: argparse.Namespace) -> Config:
    return Config(
        trusted_countries=frozenset(c.upper() for c in args.trusted_countries),
        suspicious_ports=args.suspicious_ports,
        allow_processes=frozenset(p.lower() for p in args.allow_process),
        allow_networks=parse_networks(args.allow_ip),
        alert_on_unknown=args.alert_on_unknown,
        check_country=args.provider != "none",
    )


def render(rows, alerts_only: bool, stats: str):
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        for conn, geo, reasons, sev in rows:
            if alerts_only and not reasons:
                continue
            country = geo.country if geo else "-"
            print(f"{sev:11} {conn.pid!s:>6} {conn.process:20} {conn.remote_ip}:{conn.remote_port}"
                  f" {country} {' '.join(reasons)}")
        print(stats)
        return

    console = Console()
    table = Table(title=f"Suspicious Connection Detector - {datetime.now():%H:%M:%S}",
                  caption=stats)
    for col in ("Sev", "PID", "Process", "Proto", "Remote", "Country", "Reasons"):
        table.add_column(col)
    for conn, geo, reasons, sev in rows:
        if alerts_only and not reasons:
            continue
        table.add_row(sev, str(conn.pid or "-"), conn.process[:24], conn.protocol,
                      f"{conn.remote_ip}:{conn.remote_port}",
                      geo.country if geo else "-", ", ".join(reasons),
                      style=SEVERITY_STYLE.get(sev, ""))
    console.clear()
    console.print(table)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    cfg = config_from_args(args)
    provider = build_provider(args.provider, args.geoip_db, args.timeout)
    enricher = CachedEnricher(provider, ttl=args.cache_ttl)
    detector = Detector(cfg, enricher, Deduper(args.dedupe_window))
    total_alerts = 0

    try:
        while True:
            try:
                conns = collect_connections()
            except PermissionError:
                print("Permission denied reading connections. Run as Administrator/root.",
                      file=sys.stderr)
                return 2
            rows, alerts = detector.scan(conns)
            if alerts:
                total_alerts += write_jsonl(args.log, alerts)
            if args.json:
                for a in alerts:
                    print(a.to_json(), flush=True)
            else:
                stats = (f"{len(rows)} connections | {total_alerts} alerts logged to {args.log}"
                         f" | provider={provider.name} lookups={enricher.lookups}")
                render(rows, args.alerts_only, stats)
            if args.once:
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped by user.", file=sys.stderr)
        return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
