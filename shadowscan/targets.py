"""Scan targets. Each subclass validates and normalises its own input, so the
rest of the app can trust that a constructed target is well-formed."""

from __future__ import annotations

import ipaddress
import re
from abc import ABC, abstractmethod
from urllib.parse import urlparse


class ScanTarget(ABC):
    kind: str = ""
    label: str = ""

    def __init__(self, raw: str):
        if raw is None:
            raise ValueError(f"{self.label} cannot be empty.")
        self._value = self.normalize(raw)

    @abstractmethod
    def normalize(self, raw: str) -> str:
        """Return the cleaned value or raise ValueError with a user-facing message."""

    @property
    def value(self) -> str:
        return self._value

    @property
    def display(self) -> str:
        """Value that is safe to show on screen, in history and in reports."""
        return self._value

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.display!r})"


class EmailTarget(ScanTarget):
    kind, label = "email", "Email Address"
    _PATTERN = re.compile(r"^[\w.%+-]+@[\w.-]+\.[a-zA-Z]{2,}$")

    def normalize(self, raw):
        email = raw.strip().lower()
        if not email:
            raise ValueError("Email address cannot be empty.")
        if not self._PATTERN.match(email):
            raise ValueError(f"'{raw.strip()}' is not a valid email address.")
        return email


class PasswordTarget(ScanTarget):
    kind, label = "password", "Password"

    def normalize(self, raw):
        # Passwords are deliberately not stripped - whitespace is significant.
        if not raw:
            raise ValueError("Password cannot be empty.")
        return raw

    @property
    def display(self):
        return "•" * 8


class UsernameTarget(ScanTarget):
    kind, label = "username", "Username"

    def normalize(self, raw):
        username = raw.strip()
        if not username:
            raise ValueError("Username cannot be empty.")
        if len(username) < 3:
            raise ValueError("Username must be at least 3 characters.")
        return username


class PhoneTarget(ScanTarget):
    kind, label = "phone", "Phone Number"

    def normalize(self, raw):
        digits = re.sub(r"[\s\-().+]", "", raw.strip())
        if not digits or not digits.isdigit():
            raise ValueError(f"'{raw.strip()}' is not a valid phone number.")
        if not 7 <= len(digits) <= 15:
            raise ValueError("Phone number must have 7-15 digits (include the country code).")
        return digits


class IpTarget(ScanTarget):
    kind, label = "ip", "IP Address"

    def normalize(self, raw):
        text = raw.strip()
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            raise ValueError(f"'{text}' is not a valid IPv4 or IPv6 address.") from None


class DomainTarget(ScanTarget):
    kind, label = "domain", "Domain"
    _PATTERN = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,63}$")

    def normalize(self, raw):
        text = raw.strip().lower()
        # Accept pasted URLs like https://www.example.com/path
        if "://" in text:
            text = urlparse(text).hostname or ""
        text = text.split("/")[0].rstrip(".")
        if not text:
            raise ValueError("Domain cannot be empty.")
        if not self._PATTERN.match(text):
            raise ValueError(f"'{raw.strip()}' is not a valid domain (e.g. example.com).")
        return text


TARGET_TYPES: dict[str, type[ScanTarget]] = {
    cls.kind: cls
    for cls in (EmailTarget, PasswordTarget, UsernameTarget, PhoneTarget, IpTarget, DomainTarget)
}


def make_target(kind: str, raw: str) -> ScanTarget:
    return TARGET_TYPES[kind](raw)
