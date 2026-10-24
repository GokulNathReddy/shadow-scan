"""Colours, fonts and DPI scaling for the cyber-console look."""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import font as tkfont

BG = "#05090e"
SURFACE = "#0a1119"
SURFACE_2 = "#0f1922"
RAISED = "#14212d"
BORDER = "#1a2a39"
ACCENT = "#00e5ff"
GREEN = "#00ff9c"
TEXT = "#d6e2ec"
MUTED = "#6c8396"
DIM = "#34495c"
WARN = "#ffb300"
DANGER = "#ff3d5a"
LOG_BG = "#03070b"

_scale = 1.0
MONO = "Courier New"
UI = "Arial"
SYMBOL = "Arial"


def enable_dpi_awareness() -> None:
    """Render crisply on scaled Windows displays (must run before Tk())."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass


def init(root: tk.Tk) -> None:
    global _scale, MONO, UI, SYMBOL
    _scale = max(1.0, root.winfo_fpixels("1i") / 96.0)
    families = set(tkfont.families(root))

    def pick(*names: str) -> str:
        return next((n for n in names if n in families), names[-1])

    MONO = pick("Cascadia Mono", "Consolas", "JetBrains Mono", "DejaVu Sans Mono", "Menlo", "Courier New")
    UI = pick("Segoe UI", "Inter", "Helvetica Neue", "DejaVu Sans", "Arial")
    SYMBOL = pick("Segoe UI Symbol", "DejaVu Sans", UI)


def S(px: float) -> int:
    """Scale a design-time pixel size (designed at 96 DPI) to the screen."""
    return int(round(px * _scale))


def mono(size: int = 10, weight: str = "normal") -> tuple:
    return (MONO, size, weight)


def ui(size: int = 10, weight: str = "normal") -> tuple:
    return (UI, size, weight)


def symbol(size: int = 12) -> tuple:
    return (SYMBOL, size)


def blend(c1: str, c2: str, t: float) -> str:
    """Mix colour c1 towards c2 by t (0 = c1, 1 = c2)."""
    t = max(0.0, min(1.0, t))
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(a, b))
