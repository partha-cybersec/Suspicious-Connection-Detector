# Suspicious Connection Detector

![CI](https://github.com/partha-cybersec/Suspicious-Connection-Detector/actions/workflows/ci.yml/badge.svg)

A small host-based network monitor written in Python. It watches the live TCP/UDP connections on a
Windows or Linux machine, enriches each remote IP with its country, applies a few simple detection
rules, and writes alerts as **JSON Lines** so they can be shipped into a SIEM (Splunk, Elastic, Wazuh).

> Built as a learning project for SOC / blue-team work. It is a triage aid, not an EDR.

## What's new in v2

| v1 | v2 |
|----|----|
| Called ipapi.co for every IP on every 5-second loop | TTL cache (successes 1 h, failures 5 min) - each IP is looked up once |
| Looked up private / loopback IPs | Non-public IPs (RFC 1918, loopback, link-local, CGNAT, multicast) are never sent out |
| Online lookup only, always on | Pluggable providers: `none` (default - nothing leaves the host), `geolite2` (offline MaxMind DB), `ipapi` (online, opt-in) |
| Hard-coded settings | Command-line options for everything |
| Plain-text log, same alert every 5 s | JSON Lines log, UTC timestamps, de-duplicated alerts |
| Country was the only signal | Rules with reasons and severity, plus a suspicious-port heuristic (related ATT&CK technique: T1571) |
| Bare `except:` blocks | Explicit error handling; a lookup failure never crashes the loop |
| No tests | 27 unit tests (psutil and HTTP are faked) + GitHub Actions on Windows and Linux |

## Install

```bash
git clone https://github.com/partha-cybersec/Suspicious-Connection-Detector.git
cd Suspicious-Connection-Detector
pip install -r requirements.txt
```

Run from an **Administrator** terminal on Windows (or with `sudo` on Linux) so every process name is visible.

## Usage

```bash
# Live table, port rule only, nothing sent off the machine
python -m scd

# Add country checks with the online provider; trust India and the US; hide clean rows
python -m scd --provider ipapi -t IN,US --alerts-only

# Fully offline, using a local GeoLite2 database
python -m scd --provider geolite2 --geoip-db GeoLite2-Country.mmdb

# Ignore known-good software and your own network
python -m scd --allow-process chrome.exe,msedge.exe --allow-ip 192.168.1.0/24

# One scan, alerts as JSON on stdout (for scripts / piping into jq)
python -m scd --once --json
```

The old command `python suspicious_connection_detector.py` still works.

<details>
<summary>All options</summary>

| Option | Default | Meaning |
|--------|---------|---------|
| `-t, --trusted-countries` | `IN` | Comma-separated ISO codes that are not flagged |
| `-i, --interval` | `5` | Seconds between scans |
| `--once` | off | Scan once and exit |
| `--provider` | `none` | `none`, `geolite2` or `ipapi`. The country rule only runs with a provider |
| `--geoip-db` | - | Path to `GeoLite2-Country.mmdb` (needs `pip install geoip2`) |
| `--cache-ttl` | `3600` | Seconds a successful lookup is cached |
| `--timeout` | `3` | Lookup timeout in seconds |
| `--allow-process` | - | Process names never alerted on |
| `--allow-ip` | - | IPs / CIDR ranges never alerted on |
| `--suspicious-ports` | see below | Remote ports that raise an alert |
| `--alert-on-unknown` | off | Also alert when the country lookup fails |
| `--dedupe-window` | `600` | Seconds before an identical alert is logged again |
| `-o, --log` | `suspicious_connections.jsonl` | Alert log file |
| `--alerts-only` | off | Hide connections without alerts |
| `--json` | off | Print alerts as JSON instead of the table |

</details>

## Detection rules

| Rule | Severity | Why it matters | ATT&CK |
|------|----------|----------------|--------|
| Remote port in the suspicious list (`23, 1337, 4444, 4445, 5555, 6666, 6667, 6697, 9001, 12345, 31337`, change with `--suspicious-ports`) | medium | Common defaults for reverse shells, C2 frameworks, IRC bots and RATs | Heuristic for [T1571 Non-Standard Port](https://attack.mitre.org/techniques/T1571/) |
| Country is not in the trusted list (needs `--provider geolite2` or `ipapi`) | low | Unexpected geography can be worth a look | - |
| Country lookup failed (`--alert-on-unknown`) | low | Optional, for strict environments | - |

**Severity model.** Severity means "how much attention this deserves", not "confirmed malicious".
A port match is a stronger hint than geography, so it is `medium`; country alone is `low`. Two weak
signals on one connection stay `medium` - the tool never claims `high` from heuristics alone.

Country on its own is a **weak signal**: CDNs, cloud providers and update servers live all over the
world, so expect false positives and use the allowlists. The `mitre_attack` field lists a technique
the alert *may* relate to; a port match does not prove the technique is being used.

Connections whose owning process cannot be read (no admin rights) show as `?` and are never
treated as allow-listed.

## Alert format

Each alert is one JSON object per line (illustrative example):

```json
{"timestamp": "2026-10-18T09:12:44+00:00", "host": "LAPTOP-01", "event_type": "suspicious_connection",
 "severity": "medium", "reasons": ["suspicious_remote_port:4444", "untrusted_country:NL"],
 "pid": 7312, "process": "powershell.exe", "protocol": "tcp", "local": "192.168.1.20:52144",
 "remote_ip": "203.0.113.50", "remote_port": 4444, "country": "NL",
 "enrichment_status": "ok", "enrichment_source": "ipapi", "mitre_attack": ["T1571"]}
```

Quick triage with `jq`:

```bash
jq -r 'select(.severity=="medium") | [.timestamp,.process,.remote_ip,.remote_port] | @tsv' suspicious_connections.jsonl
```

## Privacy and threat model

- By default (`--provider none`) nothing is sent anywhere.
- With `--provider ipapi`, **public** remote IPs your machine talks to are sent to ipapi.co.
  Prefer `--provider geolite2` (offline) where that is not acceptable.
- Private and local addresses are never sent anywhere.
- The tool only reads connection tables; it does not block, kill or modify anything.
- Malware can use ports like 443 and trusted countries, so a clean result does not mean a clean host.

## Development

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -q
```

Project layout: `scd/enrich.py` (providers + cache), `scd/detector.py` (collection, rules,
de-duplication, JSONL), `scd/cli.py` (options and table), `tests/` (unit tests).

## Roadmap

- Optional reputation providers (AbuseIPDB / VirusTotal) behind an API key, with caching and rate limits
- Per-process baseline ("this process has never talked to this ASN before")
- Sigma rule examples for the JSONL events

## Author

**Alluri Partha Saradhi Reddy** - [github.com/partha-cybersec](https://github.com/partha-cybersec)
