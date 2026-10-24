"""Common base for every provider: network error handling lives here once,
so each concrete provider only implements the API-specific parsing."""

from __future__ import annotations

import urllib.error
from abc import ABC, abstractmethod
from typing import Callable

from ..models import ScanResult
from ..targets import ScanTarget

# log(level, message) where level is "info", "sys", "warn" or "err"
Logger = Callable[[str, str], None]


def _silent(level: str, message: str) -> None:
    pass


class BreachProvider(ABC):
    name: str = "Provider"
    host: str = ""  # used by the diagnostics screen
    target_types: tuple[type[ScanTarget], ...] = ()

    def supports(self, target: ScanTarget) -> bool:
        return isinstance(target, self.target_types)

    def scan(self, target: ScanTarget, log: Logger = _silent) -> ScanResult:
        """Template method: never raises, always returns a ScanResult."""
        try:
            return self._scan(target, log)
        except TimeoutError:
            return ScanResult.error(self.name, "Request timed out. The API may be slow or unreachable.")
        except urllib.error.URLError as err:
            if isinstance(err.reason, TimeoutError):
                return ScanResult.error(self.name, "Request timed out. The API may be slow or unreachable.")
            return ScanResult.error(self.name, f"Network unreachable: {err.reason}")
        except Exception as err:  # malformed JSON, API changes, etc.
            return ScanResult.error(self.name, f"Lookup failed: {err}")

    @abstractmethod
    def _scan(self, target: ScanTarget, log: Logger) -> ScanResult:
        ...

    def status_error(self, status: int) -> ScanResult | None:
        """Shared handling for non-200 responses. Returns None for 200."""
        if status == 200:
            return None
        if status == 429:
            return ScanResult.error(self.name, f"Rate limited by {self.name}. Wait a moment and try again.")
        if status >= 500:
            return ScanResult.error(self.name, f"{self.name} is having problems (HTTP {status}). Try again later.")
        return ScanResult.error(self.name, f"{self.name} returned HTTP {status}.")
