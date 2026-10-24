"""Boot sequence: matrix rain behind a typewriter-style terminal panel."""

from __future__ import annotations

import tkinter as tk

from .. import __version__
from . import theme
from .theme import S, blend
from .widgets import MatrixRain

BANNER = (
    "███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗   ███████╗ ██████╗ █████╗ ███╗   ██╗",
    "██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║   ██╔════╝██╔════╝██╔══██╗████╗  ██║",
    "███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║   ███████╗██║     ███████║██╔██╗ ██║",
    "╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║   ╚════██║██║     ██╔══██║██║╚██╗██║",
    "███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝   ███████║╚██████╗██║  ██║██║ ╚████║",
    "╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝",
)

BOOT_LINES = (
    "Initialising Keccak-512 hashing core",
    "Loading intelligence providers: XposedOrNot, LeakCheck, AbuseIPDB, AlienVault OTX",
    "Verifying k-anonymity privacy layer",
    "Establishing encrypted uplink (TLS 1.3)",
    "Calibrating threat scoring matrix",
)


class Splash(tk.Frame):
    def __init__(self, master, on_done):
        super().__init__(master, bg=theme.BG)
        self.on_done = on_done
        self.finished = False
        self.rain = MatrixRain(self)
        self.rain.pack(fill="both", expand=True)
        self.bind_all("<Key>", self._skip, add="+")
        self.rain.bind("<Button-1>", self._skip)
        self.after(30, self._layout)

    def _layout(self):
        c = self.rain
        c.update_idletasks()
        w, h = c.winfo_width(), c.winfo_height()
        pw, ph = S(760), S(400)
        x0, y0 = (w - pw) / 2, (h - ph) / 2
        self.x0, self.y0, self.pw = x0, y0, pw
        self.panel = c.create_rectangle(x0, y0, x0 + pw, y0 + ph, fill=theme.BG,
                                        outline=blend(theme.GREEN, theme.BG, 0.4), width=S(1))
        c.create_rectangle(x0, y0, x0 + pw, y0 + S(24), fill=theme.SURFACE_2, outline="")
        for i, color in enumerate((theme.DANGER, theme.WARN, theme.GREEN)):
            cx = x0 + S(16) + i * S(16)
            c.create_oval(cx - S(4), y0 + S(8), cx + S(4), y0 + S(16), fill=color, outline="")
        c.create_text(x0 + pw / 2, y0 + S(12), text="shadowscan@console: ~/boot", font=theme.mono(8),
                      fill=theme.MUTED)
        c.below = self.panel

        self.banner_items = []
        for i, line in enumerate(BANNER):
            color = blend(theme.ACCENT, theme.GREEN, i / (len(BANNER) - 1))
            self.banner_items.append(c.create_text(x0 + pw / 2, y0 + S(54) + i * S(15), text="",
                                                   font=theme.mono(9, "bold"), fill=color))
        self.tagline = c.create_text(x0 + pw / 2, y0 + S(160), text="", font=theme.mono(9), fill=theme.MUTED)
        self.boot_items = [c.create_text(x0 + S(36), y0 + S(196) + i * S(22), text="", anchor="w",
                                         font=theme.mono(9), fill=theme.TEXT) for i in range(len(BOOT_LINES))]
        bar_y = y0 + ph - S(46)
        c.create_rectangle(x0 + S(36), bar_y, x0 + pw - S(36), bar_y + S(6), fill=theme.RAISED, outline="")
        self.bar = c.create_rectangle(x0 + S(36), bar_y, x0 + S(36), bar_y + S(6), fill=theme.GREEN, outline="")
        self.bar_y = bar_y
        self.status = c.create_text(x0 + pw / 2, bar_y + S(24), text="press any key to skip",
                                    font=theme.mono(8), fill=theme.DIM)
        c.start()
        self._reveal_banner(0, 0)

    def _reveal_banner(self, col, _):
        """Wipe the banner in left-to-right, like it's being decrypted."""
        if self.finished:
            return
        width = len(BANNER[0])
        for item, line in zip(self.banner_items, BANNER):
            self.rain.itemconfigure(item, text=line[:col].ljust(width))
        if col < width:
            self.after(12, self._reveal_banner, col + 3, 0)
        else:
            self._type_tagline(0)

    def _type_tagline(self, n):
        if self.finished:
            return
        text = f"breach intelligence console  ::  v{__version__}  ::  for educational use"
        self.rain.itemconfigure(self.tagline, text=text[:n])
        if n < len(text):
            self.after(10, self._type_tagline, n + 2)
        else:
            self._boot_line(0, 0)

    def _boot_line(self, index, n):
        if self.finished:
            return
        if index >= len(BOOT_LINES):
            self.rain.itemconfigure(self.status, text="▶  ACCESS GRANTED", fill=theme.GREEN,
                                    font=theme.mono(11, "bold"))
            self.after(650, self.finish)
            return
        line = BOOT_LINES[index]
        prefix = "[ OK ] " if n >= len(line) else "[ .. ] "
        self.rain.itemconfigure(self.boot_items[index], text=prefix + line[:n],
                                fill=theme.TEXT if n < len(line) else theme.GREEN)
        progress = (index + min(n, len(line)) / len(line)) / len(BOOT_LINES)
        x_start = self.x0 + S(36)
        self.rain.coords(self.bar, x_start, self.bar_y, x_start + (self.pw - S(72)) * progress, self.bar_y + S(6))
        if n < len(line):
            self.after(8, self._boot_line, index, n + 3)
        else:
            self.after(110, self._boot_line, index + 1, 0)

    def _skip(self, _event=None):
        self.finish()

    def finish(self):
        if self.finished:
            return
        self.finished = True
        self.rain.stop()
        self.unbind_all("<Key>")
        self.destroy()
        self.on_done()
