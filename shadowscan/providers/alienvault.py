"""AlienVault OTX - domain threat intelligence (no API key needed).

GET https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general
"""

from __future__ import annotations

from urllib.parse import quote

from .. import scoring
from ..models import RiskLevel, ScanResult
from ..net import get_json
from ..targets import DomainTarget
from .base import BreachProvider

API_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{}/general"
TRUSTED_SOURCES = {"whitelist", "majestic", "alexa", "akamai", "false_positive", "ad_network"}


class AlienVaultDomainProvider(BreachProvider):
    name = "AlienVault OTX"
    host = "otx.alienvault.com"
    target_types = (DomainTarget,)

    def _scan(self, target, log):
        log("info", f"GET {self.host}/api/v1/indicators/domain/{target.value}/general")
        resp = get_json(API_URL.format(quote(target.value)), timeout=20)
        log("info", f"HTTP {resp.status} from {self.host}")

        if resp.status == 404:
            return self._safe([])
        if error := self.status_error(resp.status):
            return error

        data = resp.data if isinstance(resp.data, dict) else {}
        validation = [v for v in data.get("validation", []) if isinstance(v, dict)]
        trusted = any(v.get("source") in TRUSTED_SOURCES for v in validation)
        reputation = [f"✔ {v.get('name')}: {v.get('message')}" for v in validation][:5]

        pulse_info = data.get("pulse_info") or {}
        count = int(pulse_info.get("count") or 0)
        if count == 0:
            return self._safe(reputation)

        log("warn", f"{count} threat-intel pulse(s) reference {target.value}")
        details = [f"Referenced by {count} AlienVault OTX threat pulse(s)"]
        related = (pulse_info.get("related") or {}).get("alienvault") or {}
        if related.get("malware_families"):
            details.append("⚠ Linked malware families: " + ", ".join(map(str, related["malware_families"][:6])))
        if related.get("adversary"):
            details.append("⚠ Linked threat actors: " + ", ".join(map(str, related["adversary"][:6])))

        pulses = pulse_info.get("pulses") or []
        if pulses:
            details.append("Recent pulses:")
            for p in pulses[:8]:
                tags = ", ".join(p.get("tags", [])[:4])
                details.append(f"• {p.get('name', 'Unnamed pulse')}" + (f"  [{tags}]" if tags else ""))
        if trusted:
            details.append("ℹ This domain is on popularity/whitelist feeds - pulses may just mention it.")
            details += reputation
        else:
            details.append("⚠ Treat links and downloads from this domain with suspicion.")

        return ScanResult(scoring.score_domain(count, trusted), "Threat intelligence found", self.name,
                          details, metadata={"pulseCount": str(count)},
                          intensity=scoring.intensity(count, 30))

    def _safe(self, reputation):
        return ScanResult(RiskLevel.SAFE, "No threat intelligence found", self.name,
                          ["No malicious pulses reference this domain on AlienVault OTX."] + reputation,
                          intensity=0.2)
