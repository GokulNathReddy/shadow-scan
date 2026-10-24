"""Tiny HTTP helper over urllib so the project needs no third-party packages."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, NamedTuple

USER_AGENT = "ShadowScan/2.0 (student security project)"
TIMEOUT = 15


class HttpResponse(NamedTuple):
    status: int
    data: Any  # parsed JSON, or None if the body was empty / not JSON


def get_json(url: str, headers: dict[str, str] | None = None, timeout: float = TIMEOUT) -> HttpResponse:
    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        **(headers or {}),
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            status, body = resp.status, resp.read()
    except urllib.error.HTTPError as err:  # 4xx / 5xx still carry a useful status
        status, body = err.code, err.read()

    text = body.decode("utf-8", errors="replace").strip()
    try:
        data = json.loads(text) if text else None
    except ValueError:
        data = None
    return HttpResponse(status, data)


def ping(host: str, timeout: float = 6) -> float | None:
    """Round-trip time in ms to https://host/, or None if unreachable.
    Any HTTP response (even 404) counts as reachable."""
    started = time.perf_counter()
    try:
        get_json(f"https://{host}/", timeout=timeout)
    except Exception:
        return None
    return (time.perf_counter() - started) * 1000
