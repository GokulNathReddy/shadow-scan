"""Intelligence providers - one class per external API (Strategy pattern)."""

from .abuseipdb import AbuseIpdbProvider
from .alienvault import AlienVaultDomainProvider
from .base import BreachProvider, Logger
from .demo import DemoProvider
from .leakcheck import LeakCheckProvider
from .xposedornot import XposedOrNotEmailProvider, XposedOrNotPasswordProvider


def default_providers() -> list[BreachProvider]:
    return [
        XposedOrNotEmailProvider(),
        XposedOrNotPasswordProvider(),
        LeakCheckProvider(),
        AbuseIpdbProvider(),
        AlienVaultDomainProvider(),
    ]


__all__ = [
    "BreachProvider", "Logger", "DemoProvider", "default_providers",
    "XposedOrNotEmailProvider", "XposedOrNotPasswordProvider", "LeakCheckProvider",
    "AbuseIpdbProvider", "AlienVaultDomainProvider",
]
