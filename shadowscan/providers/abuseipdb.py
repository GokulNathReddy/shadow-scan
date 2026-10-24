"""AbuseIPDB - IP *reputation* (abuse reports), not breach exposure.

GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90
Auth: "Key" header, read from the ABUSEIPDB_KEY environment variable / .env.
"""

from __future__ import annotations

import os
from urllib.parse import quote

from .. import scoring
from ..models import RiskLevel, ScanResult
from ..net import get_json
from ..targets import IpTarget
from .base import BreachProvider

API_URL = "https://api.abuseipdb.com/api/v2/check"
ENV_KEY = "ABUSEIPDB_KEY"


class AbuseIpdbProvider(BreachProvider):
    name = "AbuseIPDB"
    host = "api.abuseipdb.com"
    target_types = (IpTarget,)

    def _scan(self, target, log):
        api_key = os.environ.get(ENV_KEY, "").strip()
        if not api_key:
            log("err", f"{ENV_KEY} is not configured")
            return ScanResult(RiskLevel.ERROR, "API key not configured", self.name, [
                "IP reputation needs a free AbuseIPDB API key.",
                "1. Sign up at https://www.abuseipdb.com/account/api",
                "2. Open DIAGNOSTICS in the sidebar and paste the key",
                "ℹ Or turn on Demo Mode to try the module offline.",
            ])

        log("info", f"GET {self.host}/api/v2/check?ipAddress={target.value}")
        resp = get_json(f"{API_URL}?ipAddress={quote(target.value)}&maxAgeInDays=90&verbose",
                        headers={"Key": api_key})
        log("info", f"HTTP {resp.status} from {self.host}")

        if resp.status == 401:
            return ScanResult.error(self.name, "Invalid API key - check it in DIAGNOSTICS.")
        if resp.status == 422:
            return ScanResult.error(self.name, "AbuseIPDB rejected the IP address format.")
        if resp.status == 429:
            return ScanResult.error(self.name, "Daily limit reached (free tier: 1000 checks/day).")
        if error := self.status_error(resp.status):
            return error

        data = (resp.data or {}).get("data")
        if not isinstance(data, dict):
            return ScanResult.error(self.name, "Unexpected response format.")

        abuse = int(data.get("abuseConfidenceScore") or 0)
        reports = int(data.get("totalReports") or 0)
        details = [
            f"Abuse confidence score: {abuse}%",
            f"Reports in the last 90 days: {reports:,} (from {data.get('numDistinctUsers', 0)} users)",
            f"Country: {data.get('countryName') or data.get('countryCode') or 'N/A'}",
            f"ISP: {data.get('isp') or 'N/A'}",
            f"Domain: {data.get('domain') or 'N/A'}",
            f"Usage type: {data.get('usageType') or 'N/A'}",
        ]
        if data.get("isTor"):
            details.append("⚠ This IP is a known Tor exit node")
        if data.get("isWhitelisted"):
            details.append("ℹ This IP is whitelisted by AbuseIPDB (generally trusted)")
        if data.get("lastReportedAt"):
            details.append(f"Last reported: {data['lastReportedAt'][:19].replace('T', ' ')}")
        if not data.get("isPublic", True):
            details.append("ℹ This is a private/reserved address - it is not routable on the internet.")

        clean = abuse == 0 and reports == 0
        return ScanResult(scoring.score_ip_reputation(abuse, reports),
                          "Clean reputation" if clean else "Abuse reports found", self.name, details,
                          metadata={"abuseConfidenceScore": str(abuse), "totalReports": str(reports)},
                          intensity=scoring.intensity(abuse, 100) if abuse else 0.3)
