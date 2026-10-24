"""LeakCheck public API - username and phone lookups.

The public tier returns only breach *source names* and exposed field
categories, never the leaked data itself.

GET https://leakcheck.io/api/public?check={query}   (max 1 request/second)
"""

from __future__ import annotations

from urllib.parse import quote

from .. import scoring
from ..models import RiskLevel, ScanResult
from ..net import get_json
from ..targets import PhoneTarget, UsernameTarget
from .base import BreachProvider

API_URL = "https://leakcheck.io/api/public?check="


class LeakCheckProvider(BreachProvider):
    name = "LeakCheck"
    host = "leakcheck.io"
    target_types = (UsernameTarget, PhoneTarget)

    def _scan(self, target, log):
        is_phone = isinstance(target, PhoneTarget)
        log("info", f"GET {self.host}/api/public?check=<{target.kind}>")
        resp = get_json(API_URL + quote(target.value))
        log("info", f"HTTP {resp.status} from {self.host}")

        data = resp.data
        if resp.status == 404 or (isinstance(data, dict) and data.get("success") is False):
            return self._safe(target, is_phone)
        if error := self.status_error(resp.status):
            return error
        if isinstance(data, dict) and data.get("error"):
            return ScanResult.error(self.name, str(data["error"]))

        sources: list[str] = []
        fields: list[str] = []
        seen: set[str] = set()
        records = data.get("sources", []) if isinstance(data, dict) else data or []
        for src in records:
            if not isinstance(src, dict):
                continue
            name = src.get("name") or src.get("source")
            if name and name not in seen:
                seen.add(name)
                sources.append(f"{name} ({src['date']})" if src.get("date") else name)
            for f in src.get("fields", []):
                if f not in fields:
                    fields.append(f)
        if isinstance(data, dict):
            for f in data.get("fields", []):
                if f not in fields:
                    fields.append(f)

        if not sources:
            return self._safe(target, is_phone)

        found = data.get("found", len(sources)) if isinstance(data, dict) else len(sources)
        log("warn", f"{found} matching record(s) across {len(sources)} source(s)")
        details = [f"Matched {found:,} record(s) across {len(sources)} breach source(s)"]
        if fields:
            details.append("Exposed field types: " + ", ".join(fields))
        if "password" in fields:
            details.append("⚠ At least one source leaked passwords alongside this identifier")
        if is_phone:
            details.append("ℹ Phone coverage in breach databases is thinner than email coverage.")
        details.append("Breach sources:")
        details += [f"• {s}" for s in sources[:30]]
        if len(sources) > 30:
            details.append(f"• ...and {len(sources) - 30} more")
        if not is_phone:
            details.append("ℹ Common usernames match many unrelated people - treat as indicative.")

        return ScanResult(scoring.score_leakcheck(len(sources)), "Found in breach sources", self.name,
                          details, metadata={"sourceCount": str(len(sources))},
                          intensity=scoring.intensity(len(sources), 25))

    def _safe(self, target, is_phone):
        details = [f"This {target.label.lower()} was not found in LeakCheck's public breach index."]
        if is_phone:
            details.append("ℹ Phone coverage is limited - a clean result is not a guarantee.")
        return ScanResult(RiskLevel.SAFE, "Not found in breach sources", self.name, details, intensity=0.2)
