"""ScanEngine - routes a target to the provider that supports it.

The GUI only ever talks to the engine; it never knows which API is behind a
module, so providers can be swapped without touching any UI code."""

from __future__ import annotations

import time

from .models import ScanResult
from .providers import BreachProvider, DemoProvider, Logger, default_providers
from .targets import ScanTarget


class ScanEngine:
    def __init__(self, providers: list[BreachProvider] | None = None):
        self.providers = providers if providers is not None else default_providers()
        self.demo = DemoProvider()
        self.demo_mode = False

    def provider_for(self, target: ScanTarget) -> BreachProvider:
        if self.demo_mode:
            return self.demo
        for provider in self.providers:
            if provider.supports(target):
                return provider
        raise LookupError(f"No provider supports {target.label}")

    def scan(self, target: ScanTarget, log: Logger) -> ScanResult:
        provider = self.provider_for(target)
        log("sys", f"Routing {target.label.lower()} -> {provider.name}")
        started = time.perf_counter()
        result = provider.scan(target, log)
        result.elapsed = time.perf_counter() - started
        result.module = target.kind
        result.target = target.display
        return result
