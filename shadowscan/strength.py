"""Offline password strength estimation (nothing here touches the network)."""

from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass, field

# Assumed attacker speed: a single modern GPU against a fast hash.
GUESSES_PER_SECOND = 1e10

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "abc123",
    "111111", "123123", "1234567", "password1", "iloveyou", "admin", "welcome",
    "monkey", "dragon", "letmein", "football", "baseball", "sunshine", "princess",
    "qwerty123", "1q2w3e4r", "000000", "trustno1", "master", "shadow", "superman",
    "login", "passw0rd", "starwars", "hello", "freedom", "whatever", "zaq12wsx",
}

_SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiopasdfghjklzxcvbnm")
LABELS = ("Very weak", "Weak", "Fair", "Strong", "Very strong")


@dataclass
class StrengthReport:
    score: int  # 0-4
    label: str
    entropy_bits: float
    crack_time: str
    tips: list[str] = field(default_factory=list)


def _pool_size(password: str) -> int:
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation or c == " " for c in password):
        pool += 33
    if any(ord(c) > 127 for c in password):
        pool += 100
    return pool


def _has_sequence(password: str, run: int = 4) -> bool:
    low = password.lower()
    for seq in _SEQUENCES:
        for i in range(len(seq) - run + 1):
            chunk = seq[i:i + run]
            if chunk in low or chunk[::-1] in low:
                return True
    return False


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = (("year", 3.15e7), ("month", 2.6e6), ("day", 86400),
             ("hour", 3600), ("minute", 60), ("second", 1))
    if seconds > 3.15e7 * 1e9:
        return "longer than the age of the universe"
    if seconds > 3.15e7 * 1e6:
        return f"{seconds / 3.15e7 / 1e6:,.0f} million years"
    for name, size in units:
        if seconds >= size:
            n = int(seconds // size)
            return f"{n:,} {name if n == 1 else name + 's'}"
    return "instantly"


def analyze(password: str) -> StrengthReport:
    if not password:
        return StrengthReport(0, LABELS[0], 0.0, "instantly", ["Enter a password."])

    tips: list[str] = []
    bits = len(password) * math.log2(max(_pool_size(password), 1))

    if password.lower() in COMMON_PASSWORDS:
        bits = min(bits, 4)
        tips.append("This is one of the most common passwords in the world.")
    if re.search(r"(.)\1{2,}", password):
        bits *= 0.75
        tips.append("Avoid repeating the same character.")
    if _has_sequence(password):
        bits *= 0.8
        tips.append("Avoid sequences like 'abcd', '1234' or 'qwer'.")
    if re.search(r"(19|20)\d{2}", password):
        bits -= 6
        tips.append("Years and dates are easy to guess.")

    if len(password) < 12:
        tips.append("Use at least 12 characters - length matters most.")
    if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password):
        tips.append("Mix upper and lower case letters.")
    if not re.search(r"\d", password):
        tips.append("Add some digits.")
    if not re.search(r"[^A-Za-z0-9]", password):
        tips.append("Add a symbol such as ! # % or a space.")

    bits = max(bits, 0.0)
    score = 0 if bits < 28 else 1 if bits < 40 else 2 if bits < 60 else 3 if bits < 80 else 4
    seconds = (2 ** bits) / 2 / GUESSES_PER_SECOND
    return StrengthReport(score, LABELS[score], round(bits, 1), format_duration(seconds), tips)
