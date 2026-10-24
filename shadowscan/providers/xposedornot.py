"""XposedOrNot - email breach lookups and k-anonymity password checks.

Email:    GET https://api.xposedornot.com/v1/check-email/{email}
          GET https://api.xposedornot.com/v1/breach-analytics?email={email}
Password: GET https://passwords.xposedornot.com/api/v1/pass/anon/{keccak512[:10]}
"""

from __future__ import annotations

from urllib.parse import quote

from .. import scoring, strength
from ..keccak import keccak_512_hex
from ..models import RiskLevel, ScanResult
from ..net import get_json
from ..targets import EmailTarget, PasswordTarget
from .base import BreachProvider

CHECK_URL = "https://api.xposedornot.com/v1/check-email/"
ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics?email="
PASSWORD_URL = "https://passwords.xposedornot.com/api/v1/pass/anon/"
PREFIX_LENGTH = 10


class XposedOrNotEmailProvider(BreachProvider):
    name = "XposedOrNot"
    host = "api.xposedornot.com"
    target_types = (EmailTarget,)

    def _scan(self, target, log):
        email = target.value
        log("info", f"GET {self.host}/v1/check-email/<email>")
        resp = get_json(CHECK_URL + quote(email))
        log("info", f"HTTP {resp.status} from {self.host}")

        if resp.status == 404 or (isinstance(resp.data, dict) and "Error" in resp.data):
            return self._safe()
        if error := self.status_error(resp.status):
            return error

        breaches = [name for group in (resp.data or {}).get("breaches", []) for name in group]
        if not breaches:
            return self._safe()

        log("warn", f"{len(breaches)} breach record(s) matched - pulling analytics")
        details = [f"Found in {len(breaches)} known data breach(es)"]
        risk_score, extra = self._analytics(email, log)
        if "Breach timeline:" not in extra:
            details.append("Breached sites: " + ", ".join(breaches))
        details += extra

        return ScanResult(
            scoring.score_email(len(breaches), risk_score), "Breach data found", self.name, details,
            metadata={"breachCount": str(len(breaches)), "breaches": ", ".join(breaches)},
            intensity=scoring.intensity(len(breaches), 20),
        )

    def _analytics(self, email, log) -> tuple[int, list[str]]:
        """Returns (XposedOrNot risk score or -1, extra detail lines)."""
        try:
            resp = get_json(ANALYTICS_URL + quote(email))
        except Exception as err:
            log("warn", f"Analytics unavailable: {err}")
            return -1, []
        if resp.status != 200 or not isinstance(resp.data, dict):
            return -1, []

        data = resp.data
        lines: list[str] = []
        risk_score = -1
        metrics = data.get("BreachMetrics") or {}

        risk = (metrics.get("risk") or [{}])[0]
        if "risk_score" in risk:
            risk_score = int(risk["risk_score"])

        pw = (metrics.get("passwords_strength") or [{}])[0]
        if pw.get("PlainText"):
            lines.append(f"⚠ {pw['PlainText']} breach(es) stored your password in PLAIN TEXT")
        if pw.get("EasyToCrack"):
            lines.append(f"⚠ {pw['EasyToCrack']} breach(es) used easily crackable hashes")

        exposed_types: list[str] = []
        breach_lines: list[str] = []
        for b in (data.get("ExposedBreaches") or {}).get("breaches_details") or []:
            for dtype in str(b.get("xposed_data", "")).split(";"):
                dtype = dtype.strip()
                if dtype and dtype not in exposed_types:
                    exposed_types.append(dtype)
            year = b.get("xposed_date", "")
            records = b.get("xposed_records")
            size = f", {int(records):,} accounts" if isinstance(records, (int, float)) else ""
            breach_lines.append(f"• {b.get('breach', '?')} ({year}{size})")

        if exposed_types:
            lines.append("Exposed data: " + ", ".join(exposed_types))
        if risk.get("risk_label"):
            lines.append(f"XposedOrNot risk rating: {risk['risk_label']} ({risk_score}/100)")
        if breach_lines:
            lines.append("Breach timeline:")
            lines += breach_lines[:25]
            if len(breach_lines) > 25:
                lines.append(f"• ...and {len(breach_lines) - 25} more")
        if lines:
            lines.append("ℹ Change any password reused on these sites and enable 2FA.")
        return risk_score, lines

    def _safe(self):
        return ScanResult(RiskLevel.SAFE, "No breaches found", self.name,
                          ["This email was not found in any breach indexed by XposedOrNot."],
                          intensity=0.2)


class XposedOrNotPasswordProvider(BreachProvider):
    name = "XposedOrNot Passwords"
    host = "passwords.xposedornot.com"
    target_types = (PasswordTarget,)

    @staticmethod
    def hash_prefix(password: str) -> str:
        """SECURITY: the full digest only exists inside this function; only the
        first 10 hex characters ever leave it (k-anonymity)."""
        return keccak_512_hex(password.encode("utf-8"))[:PREFIX_LENGTH]

    def _scan(self, target, log):
        log("sys", "Hashing password locally with Keccak-512...")
        prefix = self.hash_prefix(target.value)
        log("sys", f"k-anonymity prefix: {prefix}  (the password itself is never sent)")
        report = strength.analyze(target.value)

        log("info", f"GET {self.host}/api/v1/pass/anon/{prefix}")
        resp = get_json(PASSWORD_URL + prefix)
        log("info", f"HTTP {resp.status} from {self.host}")

        local = [
            f"Local strength analysis: {report.label} ({report.entropy_bits:.0f} bits of entropy)",
            f"Estimated offline crack time: {report.crack_time}",
        ] + [f"ℹ {tip}" for tip in report.tips[:3]]

        data = resp.data if isinstance(resp.data, dict) else {}
        if resp.status == 404 or "Error" in data or "SearchPassAnon" not in data:
            if resp.status not in (200, 404) and (error := self.status_error(resp.status)):
                return error
            return ScanResult(
                RiskLevel.SAFE, "Not found in known breaches", self.name,
                ["This password was not found in any breach indexed by XposedOrNot."] + local,
                metadata={"hashPrefix": prefix}, intensity=0.6 - report.score * 0.15,
            )

        info = data["SearchPassAnon"]
        count = int(str(info.get("count", "0")) or 0)
        in_wordlist = str(info.get("wordlist", "0")) == "1"
        level = scoring.score_password(count, in_wordlist)

        details = [f"Seen {count:,} time(s) in leaked password dumps", f"Composition: {_describe_chars(info.get('char', ''))}"]
        if in_wordlist:
            details.append("⚠ Appears in password-cracking wordlists")
        if level in (RiskLevel.EXPOSED, RiskLevel.CRITICAL):
            details.append("⚠ Change this password everywhere you use it - attackers try it first")
        return ScanResult(level, "Password exposure detected", self.name, details + local,
                          metadata={"exposureCount": str(count), "hashPrefix": prefix},
                          intensity=scoring.intensity(len(str(count)), 8))


def _describe_chars(char_info: str) -> str:
    """'D:6;A:0;S:0;L:6' -> '6 digits, 0 letters, 0 symbols, length 6'"""
    names = {"D": "digits", "A": "letters", "S": "symbols"}
    parts, length = [], ""
    for chunk in char_info.split(";"):
        key, _, val = chunk.partition(":")
        if key in names:
            parts.append(f"{val} {names[key]}")
        elif key == "L":
            length = f"length {val}"
    return ", ".join(parts + ([length] if length else [])) or "n/a"
