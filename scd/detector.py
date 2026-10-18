"""Connection collection, detection rules, de-duplication and JSONL logging."""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional

from .enrich import CachedEnricher, LookupResult

# Ports commonly used by reverse shells, C2 frameworks, IRC botnets and
# remote-access tools. A hit is a *signal* worth a look, not proof.
DEFAULT_SUSPICIOUS_PORTS = frozenset(
    {23, 1337, 4444, 4445, 5555, 6666, 6667, 6697, 9001, 12345, 31337}
)


@dataclass
class Connection:
    pid: Optional[int]
    process: str
    protocol: str
    local: str
    remote_ip: str
    remote_port: int


@dataclass
class Alert:
    timestamp: str
    host: str
    event_type: str
    severity: str
    reasons: list
    pid: Optional[int]
    process: str
    protocol: str
    local: str
    remote_ip: str
    remote_port: int
    country: str
    enrichment_status: str
    enrichment_source: str
    mitre_attack: list = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


@dataclass
class Config:
    trusted_countries: frozenset = frozenset({"IN"})
    suspicious_ports: frozenset = DEFAULT_SUSPICIOUS_PORTS
    allow_processes: frozenset = frozenset()
    allow_networks: tuple = ()
    alert_on_unknown: bool = False
    check_country: bool = True


def parse_networks(values: Iterable[str]) -> tuple:
    nets = []
    for v in values:
        v = v.strip()
        if v:
            nets.append(ipaddress.ip_network(v, strict=False))
    return tuple(nets)


def collect_connections(psutil_mod=None) -> list[Connection]:
    """Read established TCP and connected UDP sockets from the OS."""
    if psutil_mod is None:
        import psutil as psutil_mod  # imported lazily so tests need no psutil

    names: dict[Optional[int], str] = {}

    def proc_name(pid: Optional[int]) -> str:
        if pid in names:
            return names[pid]
        try:
            name = psutil_mod.Process(pid).name() if pid else "?"
        except (psutil_mod.NoSuchProcess, psutil_mod.AccessDenied, ValueError):
            name = "?"
        names[pid] = name
        return name

    try:
        raw = psutil_mod.net_connections(kind="inet")
    except psutil_mod.AccessDenied as exc:
        # macOS and some hardened Linux setups need root for a system-wide view
        raise PermissionError(str(exc)) from exc

    out = []
    for c in raw:
        if not c.raddr:
            continue
        is_tcp = c.type == socket.SOCK_STREAM
        if is_tcp and c.status != psutil_mod.CONN_ESTABLISHED:
            continue
        out.append(Connection(
            pid=c.pid,
            process=proc_name(c.pid),
            protocol="tcp" if is_tcp else "udp",
            local=f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
            remote_ip=c.raddr.ip,
            remote_port=c.raddr.port,
        ))
    return out


def is_allowlisted(conn: Connection, cfg: Config) -> bool:
    if conn.process.lower() in cfg.allow_processes:
        return True
    try:
        ip = ipaddress.ip_address(conn.remote_ip)
    except ValueError:
        return False
    return any(ip in net for net in cfg.allow_networks)


def evaluate(conn: Connection, geo: LookupResult, cfg: Config) -> tuple[list, list, str]:
    """Return (reasons, mitre_ids, severity). Empty reasons = no alert."""
    reasons, mitre = [], []
    if conn.remote_port in cfg.suspicious_ports:
        reasons.append(f"suspicious_remote_port:{conn.remote_port}")
        mitre.append("T1571")  # Non-Standard Port
    if cfg.check_country and geo.status == "ok" and geo.country not in cfg.trusted_countries:
        reasons.append(f"untrusted_country:{geo.country}")
    if cfg.check_country and cfg.alert_on_unknown and geo.status == "error":
        reasons.append("country_lookup_failed")

    # Severity reflects confidence, and none of these heuristics is proof on its own,
    # so two weak signals together are still only "medium" (no automatic "high").
    if any(r.startswith("suspicious_remote_port") for r in reasons):
        severity = "medium"
    elif reasons:
        severity = "low"
    else:
        severity = "info"
    return reasons, mitre, severity


class Deduper:
    """Suppress repeat alerts for the same flow within ``window`` seconds."""

    def __init__(self, window: float = 600,
                 clock: Callable[[], float] = time.monotonic,
                 max_entries: int = 10000) -> None:
        self.window = window
        self.max_entries = max_entries
        self._clock = clock
        self._seen: dict[tuple, float] = {}

    def is_new(self, key: tuple) -> bool:
        now = self._clock()
        last = self._seen.get(key)
        if last is not None and now - last < self.window:
            return False
        self._seen[key] = now
        # keep memory bounded on long runs
        if len(self._seen) > self.max_entries:
            cutoff = now - self.window
            self._seen = {k: t for k, t in self._seen.items() if t > cutoff}
            if len(self._seen) > self.max_entries:  # still full: drop the oldest half
                keep = sorted(self._seen.items(), key=lambda kv: kv[1])[len(self._seen) // 2:]
                self._seen = dict(keep)
        return True


class Detector:
    def __init__(self, cfg: Config, enricher: CachedEnricher,
                 deduper: Deduper, host: Optional[str] = None) -> None:
        self.cfg = cfg
        self.enricher = enricher
        self.deduper = deduper
        self.host = host or socket.gethostname()

    def scan(self, conns: Iterable[Connection]) -> tuple[list, list]:
        """Return (rows_for_display, new_alerts)."""
        rows, alerts = [], []
        for conn in conns:
            if is_allowlisted(conn, self.cfg):
                rows.append((conn, None, [], "allowlisted"))
                continue
            geo = self.enricher.lookup(conn.remote_ip) if self.cfg.check_country \
                else LookupResult("-", "disabled", "none")
            reasons, mitre, severity = evaluate(conn, geo, self.cfg)
            rows.append((conn, geo, reasons, severity))
            if not reasons:
                continue
            key = (conn.process, conn.remote_ip, conn.remote_port, tuple(reasons))
            if not self.deduper.is_new(key):
                continue
            alerts.append(Alert(
                timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                host=self.host,
                event_type="suspicious_connection",
                severity=severity,
                reasons=reasons,
                pid=conn.pid,
                process=conn.process,
                protocol=conn.protocol,
                local=conn.local,
                remote_ip=conn.remote_ip,
                remote_port=conn.remote_port,
                country=geo.country,
                enrichment_status=geo.status,
                enrichment_source=geo.source,
                mitre_attack=mitre,
            ))
        return rows, alerts


def write_jsonl(path: str, alerts: Iterable[Alert]) -> int:
    n = 0
    with open(path, "a", encoding="utf-8") as fh:
        for a in alerts:
            fh.write(a.to_json() + "\n")
            n += 1
    return n
