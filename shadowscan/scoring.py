"""Turns raw API numbers into a normalised RiskLevel.

Thresholds are calibrated per module because each API's numbers mean
different things (breach count vs. abuse confidence vs. pulse count)."""

from __future__ import annotations

from .models import RiskLevel


def score_email(breach_count: int, api_risk_score: int = -1) -> RiskLevel:
    """api_risk_score is XposedOrNot's own 0-100 rating, or -1 if unavailable."""
    if breach_count <= 0:
        return RiskLevel.SAFE
    if api_risk_score >= 80:
        return RiskLevel.CRITICAL
    if api_risk_score >= 50:
        return RiskLevel.EXPOSED
    if breach_count >= 6:
        return RiskLevel.CRITICAL
    if breach_count >= 3:
        return RiskLevel.EXPOSED
    return RiskLevel.CAUTION


def score_password(exposure_count: int, in_wordlist: bool) -> RiskLevel:
    if exposure_count <= 0 and not in_wordlist:
        return RiskLevel.SAFE
    if exposure_count >= 10_000 or in_wordlist:
        return RiskLevel.CRITICAL
    if exposure_count >= 100:
        return RiskLevel.EXPOSED
    return RiskLevel.CAUTION


def score_leakcheck(source_count: int) -> RiskLevel:
    if source_count <= 0:
        return RiskLevel.SAFE
    if source_count >= 5:
        return RiskLevel.CRITICAL
    if source_count >= 3:
        return RiskLevel.EXPOSED
    return RiskLevel.CAUTION


def score_ip_reputation(abuse_confidence: int, total_reports: int) -> RiskLevel:
    """AbuseIPDB reports abuse, not breach exposure - the scale reflects that."""
    if abuse_confidence <= 0 and total_reports <= 0:
        return RiskLevel.SAFE
    if abuse_confidence >= 76:
        return RiskLevel.CRITICAL
    if abuse_confidence >= 26:
        return RiskLevel.EXPOSED
    return RiskLevel.CAUTION


def score_domain(pulse_count: int, trusted: bool = False) -> RiskLevel:
    """trusted = the domain is on a whitelist / popularity list, so pulses that
    merely mention it are usually noise; we cap it at CAUTION."""
    if pulse_count <= 0:
        return RiskLevel.SAFE
    if trusted:
        return RiskLevel.CAUTION
    if pulse_count > 5:
        return RiskLevel.CRITICAL
    if pulse_count > 2:
        return RiskLevel.EXPOSED
    return RiskLevel.CAUTION


def intensity(value: float, ceiling: float) -> float:
    """Linear 0..1 position used to place the gauge needle inside a band."""
    if ceiling <= 0:
        return 0.0
    return max(0.0, min(1.0, value / ceiling))
