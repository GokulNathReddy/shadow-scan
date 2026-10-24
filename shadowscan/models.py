"""Core data model shared by every module: risk levels and scan results."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(Enum):
    """Normalised verdict. Each level carries a display label, a colour and
    the slice of the 0-100 threat gauge it occupies."""

    SAFE = ("SAFE", "#00e676", (0, 20))
    CAUTION = ("CAUTION", "#ffd600", (20, 50))
    EXPOSED = ("EXPOSED", "#ff9100", (50, 75))
    CRITICAL = ("CRITICAL", "#ff1744", (75, 100))
    ERROR = ("ERROR", "#78909c", (0, 0))

    def __init__(self, label: str, color: str, band: tuple[int, int]):
        self.label = label
        self.color = color
        self.band = band

    @property
    def is_threat(self) -> bool:
        return self in (RiskLevel.EXPOSED, RiskLevel.CRITICAL)


@dataclass
class ScanResult:
    """The outcome of a single lookup, independent of which API produced it."""

    risk: RiskLevel
    status: str
    source: str
    details: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)
    # Position (0..1) inside the risk level's gauge band - purely visual.
    intensity: float = 0.5
    module: str = ""
    target: str = ""  # display-safe value (passwords are masked)
    elapsed: float = 0.0
    timestamp: float = field(default_factory=time.time)

    @property
    def score(self) -> int:
        """Threat score 0-100 used by the gauge."""
        lo, hi = self.risk.band
        return round(lo + (hi - lo) * max(0.0, min(1.0, self.intensity)))

    @classmethod
    def error(cls, source: str, message: str) -> "ScanResult":
        return cls(RiskLevel.ERROR, "Lookup failed", source, [message])

    def to_dict(self) -> dict:
        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)),
            "module": self.module,
            "target": self.target,
            "verdict": self.risk.label,
            "score": self.score,
            "status": self.status,
            "source": self.source,
            "elapsed_seconds": round(self.elapsed, 2),
            "details": list(self.details),
            "metadata": dict(self.metadata),
        }
