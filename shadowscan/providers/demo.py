"""Offline demo provider - for presenting without internet access.

Results are synthetic but deterministic (the same input always gives the same
verdict) and are clearly labelled as demo data everywhere they appear."""

from __future__ import annotations

import hashlib
import random
import time

from .. import scoring, strength
from ..models import RiskLevel, ScanResult
from ..targets import (DomainTarget, EmailTarget, IpTarget, PasswordTarget, PhoneTarget,
                       ScanTarget, UsernameTarget)
from .base import BreachProvider
from .xposedornot import XposedOrNotPasswordProvider

SAMPLE_BREACHES = [
    ("Adobe", 2013, "Emails, Passwords, Password hints"),
    ("LinkedIn", 2012, "Emails, Passwords"),
    ("Canva", 2019, "Emails, Names, Usernames, Passwords"),
    ("Dropbox", 2012, "Emails, Passwords"),
    ("MyFitnessPal", 2018, "Emails, IP addresses, Passwords, Usernames"),
    ("Zynga", 2019, "Emails, Passwords, Phone numbers, Usernames"),
    ("Dubsmash", 2018, "Emails, Names, Passwords, Usernames"),
    ("Wattpad", 2020, "Emails, IP addresses, Names, Passwords"),
    ("Animoto", 2018, "Dates of birth, Emails, Genders, Names, Passwords"),
    ("Domino's India", 2021, "Emails, Names, Phone numbers, Addresses"),
]
DEMO_TAG = "Demo dataset (offline)"


class DemoProvider(BreachProvider):
    name = DEMO_TAG
    target_types = (EmailTarget, PasswordTarget, UsernameTarget, PhoneTarget, IpTarget, DomainTarget)

    def _scan(self, target: ScanTarget, log):
        log("warn", "DEMO MODE - no network requests are made, results are synthetic")
        if isinstance(target, PasswordTarget):
            return self._password(target, log)

        rng = random.Random(hashlib.sha256(f"{target.kind}:{target.value}".encode()).digest())
        time.sleep(0.4)
        if isinstance(target, IpTarget):
            return self._ip(rng)
        if isinstance(target, DomainTarget):
            return self._domain(rng)

        count = rng.choice([0, 1, 2, 3, 4, 6, 8])
        if count == 0:
            return ScanResult(RiskLevel.SAFE, "No breaches found", DEMO_TAG,
                              [f"[DEMO] This {target.label.lower()} was not found in any known breach."],
                              intensity=0.2)
        picks = sorted(rng.sample(SAMPLE_BREACHES, count), key=lambda b: b[1])
        level = (scoring.score_email(count) if isinstance(target, EmailTarget)
                 else scoring.score_leakcheck(count))
        details = [f"[DEMO] Found in {count} sample breach(es)", "Breach timeline:"]
        details += [f"• {name} ({year}) - {data}" for name, year, data in picks]
        if any("Passwords" in p[2] for p in picks):
            details.append("⚠ Passwords were exposed in at least one of these breaches")
        return ScanResult(level, "Breach data found", DEMO_TAG, details,
                          intensity=scoring.intensity(count, 10))

    def _password(self, target, log):
        prefix = XposedOrNotPasswordProvider.hash_prefix(target.value)
        log("sys", f"Keccak-512 prefix computed locally: {prefix}")
        report = strength.analyze(target.value)
        common = target.value.lower() in strength.COMMON_PASSWORDS
        count = 9_000_000 if common else {0: 40_000, 1: 350, 2: 12}.get(report.score, 0)
        level = scoring.score_password(count, common)
        details = [f"[DEMO] Seen {count:,} time(s) in sample password dumps",
                   f"Local strength analysis: {report.label} ({report.entropy_bits:.0f} bits)",
                   f"Estimated offline crack time: {report.crack_time}"]
        details += [f"ℹ {tip}" for tip in report.tips[:3]]
        return ScanResult(level, "Password exposure detected" if count else "Not found in known breaches",
                          DEMO_TAG, details, metadata={"hashPrefix": prefix},
                          intensity=scoring.intensity(len(str(count)), 8) if count else 0.2)

    def _ip(self, rng):
        abuse = rng.choice([0, 0, 12, 48, 100])
        reports = 0 if abuse == 0 else rng.randint(abuse, abuse * 20)
        details = [f"[DEMO] Abuse confidence score: {abuse}%",
                   f"Reports in the last 90 days: {reports:,}",
                   f"Country: {rng.choice(['India', 'Germany', 'United States', 'Netherlands'])}",
                   f"Usage type: {rng.choice(['Data Center/Web Hosting/Transit', 'Fixed Line ISP', 'Mobile ISP'])}"]
        if abuse == 100:
            details.append("⚠ This IP is a known Tor exit node")
        return ScanResult(scoring.score_ip_reputation(abuse, reports),
                          "Clean reputation" if not reports else "Abuse reports found", DEMO_TAG, details,
                          intensity=abuse / 100 if abuse else 0.3)

    def _domain(self, rng):
        pulses = rng.choice([0, 0, 2, 4, 9])
        details = [f"[DEMO] Referenced by {pulses} sample threat pulse(s)"]
        if pulses:
            details.append("Recent pulses:")
            details += [f"• {name}" for name in rng.sample(
                ["Phishing kit hosting", "Emotet C2 infrastructure", "Credential harvesting campaign",
                 "Typosquatting cluster", "Malvertising redirect chain"], min(pulses, 3))]
        return ScanResult(scoring.score_domain(pulses), "Threat intelligence found" if pulses
                          else "No threat intelligence found", DEMO_TAG, details,
                          intensity=scoring.intensity(pulses, 15))
