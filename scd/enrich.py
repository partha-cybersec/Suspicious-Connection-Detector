"""IP enrichment providers with caching.

Providers answer one question: "which country is this IP in?".
Lookups are cached (successes and failures) so the same IP is not
queried again until its TTL expires.
"""

from __future__ import annotations

import ipaddress
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional, Protocol

UNKNOWN = "??"


def is_public_ip(ip: str) -> bool:
    """True only for globally routable addresses worth enriching."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # IPv4-mapped IPv6 (::ffff:1.2.3.4) -> judge the IPv4 part
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


@dataclass
class LookupResult:
    country: str          # ISO-3166 alpha-2, or UNKNOWN
    status: str           # "ok" | "error" | "skipped" | "disabled"
    source: str           # provider name


class Provider(Protocol):
    name: str

    def country(self, ip: str) -> str:
        """Return an ISO country code. Raise on failure."""
        ...


class IpApiProvider:
    """Online lookup via https://ipapi.co (free tier, rate limited)."""

    name = "ipapi"

    def __init__(self, timeout: float = 3.0,
                 opener: Callable = urllib.request.urlopen) -> None:
        self.timeout = timeout
        self._open = opener

    def country(self, ip: str) -> str:
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={"User-Agent": "scd/2.0"})
        with self._open(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("error"):
            raise RuntimeError(data.get("reason", "lookup error"))
        code = data.get("country_code") or data.get("country")
        if not code or len(code) != 2:
            raise RuntimeError("no country in response")
        return code.upper()


class GeoLite2Provider:
    """Offline lookup using a local MaxMind GeoLite2-Country.mmdb file."""

    name = "geolite2"

    def __init__(self, db_path: str) -> None:
        try:
            import geoip2.database  # type: ignore
        except ImportError as exc:  # pragma: no cover - depends on env
            raise SystemExit(
                "geoip2 is not installed. Run: pip install geoip2"
            ) from exc
        self._reader = geoip2.database.Reader(db_path)

    def country(self, ip: str) -> str:
        code = self._reader.country(ip).country.iso_code
        if not code:
            raise RuntimeError("no country in database")
        return code


class NoProvider:
    """Enrichment disabled (fully offline, no GeoIP)."""

    name = "none"

    def country(self, ip: str) -> str:  # pragma: no cover - never called
        raise RuntimeError("disabled")


class CachedEnricher:
    """Wraps a provider with a TTL cache.

    Successful lookups are cached for ``ttl`` seconds, failures for
    ``fail_ttl`` seconds so an outage or rate limit is not hammered.
    """

    def __init__(self, provider: Provider, ttl: float = 3600,
                 fail_ttl: float = 300,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.provider = provider
        self.ttl = ttl
        self.fail_ttl = fail_ttl
        self._clock = clock
        self._cache: dict[str, tuple[float, LookupResult]] = {}
        self.lookups = 0  # number of real provider calls (for stats/tests)

    def lookup(self, ip: str) -> LookupResult:
        if isinstance(self.provider, NoProvider):
            return LookupResult(UNKNOWN, "disabled", self.provider.name)
        if not is_public_ip(ip):
            return LookupResult("LAN", "skipped", "local")

        now = self._clock()
        hit = self._cache.get(ip)
        if hit and hit[0] > now:
            return hit[1]

        self.lookups += 1
        try:
            result = LookupResult(self.provider.country(ip), "ok",
                                  self.provider.name)
            expires = now + self.ttl
        except (urllib.error.URLError, OSError, ValueError,
                RuntimeError, KeyError) as exc:
            result = LookupResult(UNKNOWN, "error", f"{self.provider.name}: {exc}"[:120])
            expires = now + self.fail_ttl
        except Exception as exc:  # noqa: BLE001 - provider libs vary
            result = LookupResult(UNKNOWN, "error", f"{self.provider.name}: {exc}"[:120])
            expires = now + self.fail_ttl
        self._cache[ip] = (expires, result)
        return result


def build_provider(name: str, geoip_db: Optional[str], timeout: float) -> Provider:
    if name == "ipapi":
        return IpApiProvider(timeout=timeout)
    if name == "geolite2":
        if not geoip_db:
            raise SystemExit("--geoip-db is required with --provider geolite2")
        return GeoLite2Provider(geoip_db)
    return NoProvider()
