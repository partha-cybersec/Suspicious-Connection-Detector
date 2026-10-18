"""Unit tests. No network and no live sockets needed: providers and psutil are faked."""

import io
import json
import os
import socket
import tempfile
import unittest
import urllib.error
from types import SimpleNamespace

from scd.cli import build_parser, config_from_args
from scd.detector import (
    Config,
    Connection,
    Deduper,
    Detector,
    collect_connections,
    evaluate,
    is_allowlisted,
    parse_networks,
    write_jsonl,
)
from scd.enrich import CachedEnricher, IpApiProvider, LookupResult, NoProvider, is_public_ip


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class FakeProvider:
    name = "fake"

    def __init__(self, answers=None, exc=None):
        self.answers = answers or {}
        self.exc = exc
        self.calls = []

    def country(self, ip):
        self.calls.append(ip)
        if self.exc:
            raise self.exc
        return self.answers.get(ip, "US")


def conn(ip="8.8.8.8", port=443, proc="app.exe", pid=10):
    return Connection(pid=pid, process=proc, protocol="tcp", local="10.0.0.2:5000",
                      remote_ip=ip, remote_port=port)


class TestPublicIp(unittest.TestCase):
    def test_private_and_special_ranges_are_skipped(self):
        for ip in ["10.1.2.3", "192.168.0.1", "172.16.5.5", "127.0.0.1", "::1",
                   "169.254.1.1", "fe80::1", "100.64.0.1", "224.0.0.1", "0.0.0.0",
                   "::ffff:192.168.1.1", "not-an-ip"]:
            self.assertFalse(is_public_ip(ip), ip)

    def test_public(self):
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"]:
            self.assertTrue(is_public_ip(ip), ip)


class TestCachedEnricher(unittest.TestCase):
    def test_success_is_cached_until_ttl(self):
        clock, prov = FakeClock(), FakeProvider({"8.8.8.8": "US"})
        e = CachedEnricher(prov, ttl=60, clock=clock)
        self.assertEqual(e.lookup("8.8.8.8").country, "US")
        e.lookup("8.8.8.8")
        self.assertEqual(len(prov.calls), 1)
        clock.t += 61
        e.lookup("8.8.8.8")
        self.assertEqual(len(prov.calls), 2)

    def test_failure_is_cached_briefly(self):
        clock = FakeClock()
        prov = FakeProvider(exc=urllib.error.URLError("timed out"))
        e = CachedEnricher(prov, ttl=3600, fail_ttl=30, clock=clock)
        r = e.lookup("1.1.1.1")
        self.assertEqual((r.country, r.status), ("??", "error"))
        e.lookup("1.1.1.1")
        self.assertEqual(len(prov.calls), 1)
        clock.t += 31
        e.lookup("1.1.1.1")
        self.assertEqual(len(prov.calls), 2)

    def test_private_ip_never_reaches_provider(self):
        prov = FakeProvider()
        r = CachedEnricher(prov).lookup("192.168.1.10")
        self.assertEqual(r.status, "skipped")
        self.assertEqual(prov.calls, [])

    def test_disabled_provider(self):
        self.assertEqual(CachedEnricher(NoProvider()).lookup("8.8.8.8").status, "disabled")

    def test_unexpected_provider_exception_does_not_crash(self):
        prov = FakeProvider(exc=ZeroDivisionError("boom"))
        self.assertEqual(CachedEnricher(prov).lookup("8.8.8.8").status, "error")


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestIpApiProvider(unittest.TestCase):
    def test_parses_country_code(self):
        p = IpApiProvider(opener=lambda req, timeout: FakeResp(b'{"country_code": "de"}'))
        self.assertEqual(p.country("8.8.8.8"), "DE")

    def test_rate_limit_error_raises(self):
        body = b'{"error": true, "reason": "RateLimited"}'
        p = IpApiProvider(opener=lambda req, timeout: FakeResp(body))
        with self.assertRaises(RuntimeError):
            p.country("8.8.8.8")


class TestRules(unittest.TestCase):
    ok_us = LookupResult("US", "ok", "fake")
    ok_in = LookupResult("IN", "ok", "fake")
    err = LookupResult("??", "error", "fake")

    def test_trusted_country_no_alert(self):
        reasons, _, sev = evaluate(conn(), self.ok_in, Config())
        self.assertEqual((reasons, sev), ([], "info"))

    def test_untrusted_country_is_low(self):
        reasons, mitre, sev = evaluate(conn(), self.ok_us, Config())
        self.assertEqual(reasons, ["untrusted_country:US"])
        self.assertEqual((mitre, sev), ([], "low"))

    def test_suspicious_port_maps_t1571(self):
        reasons, mitre, sev = evaluate(conn(port=4444), self.ok_in, Config())
        self.assertEqual(reasons, ["suspicious_remote_port:4444"])
        self.assertEqual((mitre, sev), (["T1571"], "medium"))

    def test_port_and_country_is_not_escalated_to_high(self):
        reasons, _, sev = evaluate(conn(port=4444), self.ok_us, Config())
        self.assertEqual(len(reasons), 2)
        self.assertEqual(sev, "medium")

    def test_8888_not_in_default_ports(self):
        self.assertEqual(evaluate(conn(port=8888), self.ok_in, Config())[0], [])

    def test_country_rule_off_when_provider_none(self):
        cfg = Config(check_country=False)
        self.assertEqual(evaluate(conn(), self.ok_us, cfg)[0], [])

    def test_ipv6_remote(self):
        reasons, _, _ = evaluate(conn(ip="2001:db8::1", port=4444), self.ok_in, Config())
        self.assertEqual(reasons, ["suspicious_remote_port:4444"])

    def test_unknown_process_is_never_implicitly_allowlisted(self):
        cfg = Config(allow_processes=frozenset({"chrome.exe"}))
        self.assertFalse(is_allowlisted(conn(proc="?", pid=None), cfg))

    def test_lookup_error_silent_by_default(self):
        self.assertEqual(evaluate(conn(), self.err, Config())[0], [])
        self.assertEqual(evaluate(conn(), self.err, Config(alert_on_unknown=True))[0],
                         ["country_lookup_failed"])

    def test_allowlist_process_and_cidr(self):
        cfg = Config(allow_processes=frozenset({"chrome.exe"}),
                     allow_networks=parse_networks(["142.250.0.0/15"]))
        self.assertTrue(is_allowlisted(conn(proc="Chrome.EXE"), cfg))
        self.assertTrue(is_allowlisted(conn(ip="142.251.10.10"), cfg))
        self.assertFalse(is_allowlisted(conn(ip="8.8.8.8"), cfg))


class TestDetector(unittest.TestCase):
    def make(self, clock):
        enricher = CachedEnricher(FakeProvider({"8.8.8.8": "US"}), clock=clock)
        return Detector(Config(), enricher, Deduper(600, clock=clock), host="test")

    def test_dedupes_repeat_alerts_within_window(self):
        clock = FakeClock()
        d = self.make(clock)
        _, a1 = d.scan([conn()])
        _, a2 = d.scan([conn()])
        self.assertEqual((len(a1), len(a2)), (1, 0))
        clock.t += 601
        _, a3 = d.scan([conn()])
        self.assertEqual(len(a3), 1)

    def test_dedupe_memory_stays_bounded(self):
        clock = FakeClock()
        dd = Deduper(window=600, clock=clock, max_entries=100)
        for i in range(1000):
            self.assertTrue(dd.is_new(("p", f"8.8.{i // 256}.{i % 256}", 443)))
        self.assertLessEqual(len(dd._seen), 101)

    def test_dedupe_prunes_expired_entries(self):
        clock = FakeClock()
        dd = Deduper(window=10, clock=clock, max_entries=5)
        for i in range(5):
            dd.is_new(("old", i))
        clock.t += 11
        dd.is_new(("new", 1))
        self.assertEqual(list(dd._seen), [("new", 1)])

    def test_alert_fields_and_jsonl(self):
        d = self.make(FakeClock())
        _, alerts = d.scan([conn(port=4444)])
        a = alerts[0]
        self.assertEqual(a.severity, "medium")
        self.assertEqual(a.mitre_attack, ["T1571"])
        self.assertTrue(a.timestamp.endswith("+00:00"))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.jsonl")
            self.assertEqual(write_jsonl(path, alerts), 1)
            with open(path, encoding="utf-8") as fh:
                event = json.loads(fh.readline())
        for key in ("timestamp", "host", "severity", "reasons", "pid", "process",
                    "remote_ip", "remote_port", "country", "enrichment_status", "mitre_attack"):
            self.assertIn(key, event)


class TestCollect(unittest.TestCase):
    def test_filters_listening_and_non_established(self):
        class NoSuchProcess(Exception):
            pass

        class AccessDenied(Exception):
            pass

        def addr(ip, port):
            return SimpleNamespace(ip=ip, port=port)

        rows = [
            SimpleNamespace(pid=1, type=socket.SOCK_STREAM, status="ESTABLISHED",
                            laddr=addr("10.0.0.2", 1), raddr=addr("8.8.8.8", 443)),
            SimpleNamespace(pid=2, type=socket.SOCK_STREAM, status="LISTEN",
                            laddr=addr("0.0.0.0", 80), raddr=()),
            SimpleNamespace(pid=3, type=socket.SOCK_STREAM, status="TIME_WAIT",
                            laddr=addr("10.0.0.2", 2), raddr=addr("1.1.1.1", 443)),
            SimpleNamespace(pid=4, type=socket.SOCK_DGRAM, status="NONE",
                            laddr=addr("10.0.0.2", 3), raddr=addr("9.9.9.9", 53)),
        ]

        def process(pid):
            if pid == 4:
                raise AccessDenied()
            return SimpleNamespace(name=lambda: f"p{pid}")

        fake = SimpleNamespace(net_connections=lambda kind: rows, Process=process,
                               CONN_ESTABLISHED="ESTABLISHED",
                               NoSuchProcess=NoSuchProcess, AccessDenied=AccessDenied)
        out = collect_connections(fake)
        self.assertEqual([(c.pid, c.protocol, c.process) for c in out],
                         [(1, "tcp", "p1"), (4, "udp", "?")])


class TestCollectPermissions(unittest.TestCase):
    def test_access_denied_becomes_permission_error(self):
        class AccessDenied(Exception):
            pass

        def denied(kind):
            raise AccessDenied("need root")

        fake = SimpleNamespace(net_connections=denied, AccessDenied=AccessDenied)
        with self.assertRaises(PermissionError):
            collect_connections(fake)


class TestCli(unittest.TestCase):
    def test_default_provider_is_offline(self):
        args = build_parser().parse_args([])
        self.assertEqual(args.provider, "none")
        self.assertFalse(config_from_args(args).check_country)

    def test_args_to_config(self):
        args = build_parser().parse_args(
            ["-t", "in,us", "--allow-process", "Chrome.exe", "--allow-ip", "10.0.0.0/8",
             "--suspicious-ports", "4444,1337", "--provider", "none"])
        cfg = config_from_args(args)
        self.assertEqual(cfg.trusted_countries, frozenset({"IN", "US"}))
        self.assertEqual(cfg.suspicious_ports, frozenset({4444, 1337}))
        self.assertIn("chrome.exe", cfg.allow_processes)
        self.assertFalse(cfg.check_country)


if __name__ == "__main__":
    unittest.main()
