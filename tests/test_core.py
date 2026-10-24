"""Unit tests for the non-GUI core. Run with:  python -m unittest discover tests"""

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from shadowscan import config, scoring, strength
from shadowscan.engine import ScanEngine
from shadowscan.keccak import _sponge, keccak_512_hex
from shadowscan.models import RiskLevel, ScanResult
from shadowscan.net import HttpResponse
from shadowscan.providers import (AbuseIpdbProvider, AlienVaultDomainProvider, LeakCheckProvider,
                                  XposedOrNotEmailProvider, XposedOrNotPasswordProvider)
from shadowscan.targets import (DomainTarget, EmailTarget, IpTarget, PasswordTarget, PhoneTarget,
                                UsernameTarget, make_target)


class TargetTests(unittest.TestCase):
    def test_email_normalised(self):
        self.assertEqual(EmailTarget("  User@Example.COM ").value, "user@example.com")

    def test_email_rejected(self):
        for bad in ("", "   ", "no-at-sign", "a@b", "@example.com"):
            with self.assertRaises(ValueError):
                EmailTarget(bad)

    def test_password_kept_verbatim_and_masked(self):
        t = PasswordTarget("  secret ")
        self.assertEqual(t.value, "  secret ")
        self.assertNotIn("secret", t.display)
        self.assertNotIn("secret", repr(t))

    def test_phone_strips_formatting(self):
        self.assertEqual(PhoneTarget("+1 (202) 555-0143").value, "12025550143")
        with self.assertRaises(ValueError):
            PhoneTarget("12ab34")
        with self.assertRaises(ValueError):
            PhoneTarget("123")

    def test_ip_v4_and_v6(self):
        self.assertEqual(IpTarget(" 8.8.8.8 ").value, "8.8.8.8")
        self.assertEqual(IpTarget("2001:4860:4860::8888").value, "2001:4860:4860::8888")
        for bad in ("256.1.1.1", "1.2.3", "hello"):
            with self.assertRaises(ValueError):
                IpTarget(bad)

    def test_domain_accepts_urls(self):
        self.assertEqual(DomainTarget("https://WWW.Example.com/login?x=1").value, "www.example.com")
        for bad in ("localhost", "-bad.com", "exa mple.com", ""):
            with self.assertRaises(ValueError):
                DomainTarget(bad)

    def test_username_min_length(self):
        self.assertEqual(UsernameTarget(" neo42 ").value, "neo42")
        with self.assertRaises(ValueError):
            UsernameTarget("ab")

    def test_factory(self):
        self.assertIsInstance(make_target("domain", "example.com"), DomainTarget)


class KeccakTests(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(keccak_512_hex(b"")[:32], "0eab42de4c3ceb9235fc91acffe746b2")
        self.assertEqual(keccak_512_hex(b"123456")[:10], "808d63ba47")

    def test_permutation_matches_sha3(self):
        # SHA3-512 is the same sponge with a different padding byte, so this
        # cross-checks our Keccak-f permutation against hashlib across block sizes.
        for msg in (b"", b"abc", b"x" * 71, b"x" * 72, b"y" * 300):
            self.assertEqual(_sponge(msg, 72, 64, 0x06).hex(), hashlib.sha3_512(msg).hexdigest())

    def test_prefix_is_ten_hex_chars(self):
        prefix = XposedOrNotPasswordProvider.hash_prefix("hunter2")
        self.assertEqual(len(prefix), 10)
        int(prefix, 16)


class ScoringTests(unittest.TestCase):
    def test_email(self):
        self.assertIs(scoring.score_email(0), RiskLevel.SAFE)
        self.assertIs(scoring.score_email(1), RiskLevel.CAUTION)
        self.assertIs(scoring.score_email(3), RiskLevel.EXPOSED)
        self.assertIs(scoring.score_email(6), RiskLevel.CRITICAL)
        self.assertIs(scoring.score_email(1, api_risk_score=90), RiskLevel.CRITICAL)

    def test_password(self):
        self.assertIs(scoring.score_password(0, False), RiskLevel.SAFE)
        self.assertIs(scoring.score_password(5, False), RiskLevel.CAUTION)
        self.assertIs(scoring.score_password(500, False), RiskLevel.EXPOSED)
        self.assertIs(scoring.score_password(5, True), RiskLevel.CRITICAL)

    def test_ip_and_domain(self):
        self.assertIs(scoring.score_ip_reputation(0, 0), RiskLevel.SAFE)
        self.assertIs(scoring.score_ip_reputation(80, 3), RiskLevel.CRITICAL)
        self.assertIs(scoring.score_domain(9), RiskLevel.CRITICAL)
        self.assertIs(scoring.score_domain(9, trusted=True), RiskLevel.CAUTION)

    def test_score_stays_in_band(self):
        for level in (RiskLevel.SAFE, RiskLevel.CAUTION, RiskLevel.EXPOSED, RiskLevel.CRITICAL):
            for intensity in (-1, 0, 0.5, 1, 7):
                score = ScanResult(level, "", "", intensity=intensity).score
                self.assertTrue(level.band[0] <= score <= level.band[1])


class StrengthTests(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        self.assertEqual(strength.analyze("password1").score, 0)

    def test_long_random_is_strong(self):
        self.assertGreaterEqual(strength.analyze("xK#9vL2!qP7@mZw").score, 3)

    def test_empty(self):
        self.assertEqual(strength.analyze("").score, 0)


def fake_get(responses):
    """Patch get_json in a provider module with canned responses keyed by URL substring."""
    def _get(url, headers=None, timeout=None):
        for key, resp in responses.items():
            if key in url:
                return resp
        return HttpResponse(404, None)
    return _get


class ProviderTests(unittest.TestCase):
    def test_email_breached(self):
        responses = {
            "check-email": HttpResponse(200, {"breaches": [["Adobe", "Canva", "LinkedIn"]]}),
            "breach-analytics": HttpResponse(200, {
                "BreachMetrics": {"risk": [{"risk_label": "High", "risk_score": 60}]},
                "ExposedBreaches": {"breaches_details": [
                    {"breach": "Adobe", "xposed_date": "2013", "xposed_data": "Emails;Passwords"}]},
            }),
        }
        with mock.patch("shadowscan.providers.xposedornot.get_json", fake_get(responses)):
            r = XposedOrNotEmailProvider().scan(EmailTarget("a@b.com"))
        self.assertIs(r.risk, RiskLevel.EXPOSED)
        self.assertTrue(any("Emails, Passwords" in d for d in r.details))

    def test_email_not_found(self):
        with mock.patch("shadowscan.providers.xposedornot.get_json", fake_get({})):
            r = XposedOrNotEmailProvider().scan(EmailTarget("a@b.com"))
        self.assertIs(r.risk, RiskLevel.SAFE)

    def test_password_only_sends_prefix(self):
        seen = []

        def spy(url, headers=None, timeout=None):
            seen.append(url)
            return HttpResponse(200, {"SearchPassAnon": {"count": "50000", "char": "D:6;A:0;S:0;L:6", "wordlist": 0}})

        with mock.patch("shadowscan.providers.xposedornot.get_json", spy):
            r = XposedOrNotPasswordProvider().scan(PasswordTarget("123456"))
        self.assertIs(r.risk, RiskLevel.CRITICAL)
        self.assertEqual(len(seen), 1)
        self.assertNotIn("123456", seen[0])
        self.assertTrue(seen[0].endswith("/808d63ba47"))

    def test_leakcheck_sources(self):
        data = {"success": True, "found": 4, "fields": ["password", "email"],
                "sources": [{"name": "A.com", "date": "2020-01"}, {"name": "B.com"}, {"name": "A.com"}]}
        with mock.patch("shadowscan.providers.leakcheck.get_json", fake_get({"leakcheck": HttpResponse(200, data)})):
            r = LeakCheckProvider().scan(UsernameTarget("neo42"))
        self.assertIs(r.risk, RiskLevel.CAUTION)
        self.assertEqual(r.metadata["sourceCount"], "2")

    def test_abuseipdb_requires_key(self):
        with mock.patch.dict(os.environ, {"ABUSEIPDB_KEY": ""}):
            r = AbuseIpdbProvider().scan(IpTarget("1.2.3.4"))
        self.assertIs(r.risk, RiskLevel.ERROR)

    def test_alienvault_trusted_domain_capped(self):
        data = {"validation": [{"source": "whitelist", "name": "Whitelisted", "message": "ok"}],
                "pulse_info": {"count": 40, "pulses": []}}
        with mock.patch("shadowscan.providers.alienvault.get_json", fake_get({"otx": HttpResponse(200, data)})):
            r = AlienVaultDomainProvider().scan(DomainTarget("example.com"))
        self.assertIs(r.risk, RiskLevel.CAUTION)

    def test_network_errors_become_error_results(self):
        def boom(*a, **k):
            raise TimeoutError()
        with mock.patch("shadowscan.providers.alienvault.get_json", boom):
            r = AlienVaultDomainProvider().scan(DomainTarget("example.com"))
        self.assertIs(r.risk, RiskLevel.ERROR)
        self.assertIn("timed out", r.details[0])

    def test_rate_limit(self):
        with mock.patch("shadowscan.providers.leakcheck.get_json", fake_get({"leakcheck": HttpResponse(429, None)})):
            r = LeakCheckProvider().scan(PhoneTarget("+911234567890"))
        self.assertIs(r.risk, RiskLevel.ERROR)


class EngineTests(unittest.TestCase):
    def test_routes_every_target_type(self):
        engine = ScanEngine()
        for kind, value in (("email", "a@b.com"), ("password", "x"), ("username", "abc"),
                            ("phone", "1234567"), ("ip", "1.1.1.1"), ("domain", "a.com")):
            self.assertTrue(engine.provider_for(make_target(kind, value)).supports(make_target(kind, value)))

    def test_demo_mode_is_offline_and_deterministic(self):
        engine = ScanEngine()
        engine.demo_mode = True
        with mock.patch("shadowscan.net.urllib.request.urlopen", side_effect=AssertionError("network used")):
            a = engine.scan(EmailTarget("demo@example.com"), lambda *_: None)
            b = engine.scan(EmailTarget("demo@example.com"), lambda *_: None)
        self.assertEqual((a.risk, a.details), (b.risk, b.details))
        self.assertEqual(a.module, "email")


class ConfigTests(unittest.TestCase):
    def test_env_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {}, clear=False):
            path = Path(tmp) / ".env"
            path.write_text("# comment\nOTHER=1\n", encoding="utf-8")
            config.save_env_value("SS_TEST_KEY", "abc123", path)
            self.assertIn("OTHER=1", path.read_text(encoding="utf-8"))
            os.environ.pop("SS_TEST_KEY", None)
            config.load_env(path)
            self.assertEqual(os.environ.get("SS_TEST_KEY"), "abc123")
            os.environ.pop("SS_TEST_KEY", None)


if __name__ == "__main__":
    unittest.main()
