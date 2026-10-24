"""Custom-drawn widgets: buttons, inputs, radar/threat gauge, matrix rain."""

from __future__ import annotations

import math
import random
import tkinter as tk
from tkinter import font as tkfont

from ..models import RiskLevel, ScanResult
from . import theme
from .theme import S, blend


class FlatButton(tk.Label):
    """A flat, hover-highlighted button (tk.Button can't be fully restyled on Windows)."""

    def __init__(self, master, text, command, *, bg=theme.RAISED, fg=theme.TEXT,
                 hover_bg=None, hover_fg=None, font=None, padx=16, pady=7, **kw):
        super().__init__(master, text=text, bg=bg, fg=fg, font=font or theme.ui(9, "bold"),
                         padx=S(padx), pady=S(pady), cursor="hand2", **kw)
        self._colors = (bg, fg, hover_bg or blend(bg, "#ffffff", 0.12), hover_fg or fg)
        self._command = command
        self._enabled = True
        self.bind("<Enter>", lambda e: self._paint(hover=True))
        self.bind("<Leave>", lambda e: self._paint(hover=False))
        self.bind("<Button-1>", self._click)

    def _paint(self, hover: bool):
        bg, fg, hbg, hfg = self._colors
        if not self._enabled:
            self.configure(bg=blend(bg, theme.BG, 0.5), fg=blend(fg, theme.BG, 0.5))
        else:
            self.configure(bg=hbg if hover else bg, fg=hfg if hover else fg)

    def _click(self, _event):
        if self._enabled and self._command:
            self._command()

    def set_enabled(self, enabled: bool, text: str | None = None):
        self._enabled = enabled
        self.configure(cursor="hand2" if enabled else "arrow")
        if text is not None:
            self.configure(text=text)
        self._paint(hover=False)


class NavItem(tk.Frame):
    """Sidebar entry with an accent bar that lights up when selected."""

    def __init__(self, master, icon, text, command, shortcut=""):
        super().__init__(master, bg=theme.SURFACE, cursor="hand2")
        self._command = command
        self.selected = False
        self.bar = tk.Frame(self, bg=theme.SURFACE, width=S(3))
        self.bar.pack(side="left", fill="y")
        self.icon = tk.Label(self, text=icon, font=theme.symbol(13), width=2,
                             bg=theme.SURFACE, fg=theme.MUTED)
        self.icon.pack(side="left", padx=(S(12), S(6)), pady=S(7))
        self.label = tk.Label(self, text=text, font=theme.ui(10), bg=theme.SURFACE, fg=theme.TEXT, anchor="w")
        self.label.pack(side="left", fill="x", expand=True)
        self.hint = tk.Label(self, text=shortcut, font=theme.mono(8), bg=theme.SURFACE, fg=theme.DIM)
        self.hint.pack(side="right", padx=S(10))
        for w in (self, self.icon, self.label, self.hint):
            w.bind("<Enter>", lambda e: self._paint(True))
            w.bind("<Leave>", lambda e: self._paint(False))
            w.bind("<Button-1>", lambda e: self._command())

    def set_selected(self, selected: bool):
        self.selected = selected
        self._paint(False)

    def _paint(self, hover: bool):
        bg = theme.RAISED if self.selected else (theme.SURFACE_2 if hover else theme.SURFACE)
        for w in (self, self.icon, self.label, self.hint):
            w.configure(bg=bg)
        self.bar.configure(bg=theme.ACCENT if self.selected else bg)
        self.icon.configure(fg=theme.ACCENT if self.selected else theme.MUTED)
        self.label.configure(font=theme.ui(10, "bold" if self.selected else "normal"))


class Card(tk.Frame):
    """Bordered panel with a small upper-case title row."""

    def __init__(self, master, title="", **kw):
        super().__init__(master, bg=theme.SURFACE, highlightthickness=1,
                         highlightbackground=theme.BORDER, **kw)
        self.header = tk.Frame(self, bg=theme.SURFACE)
        if title:
            self.header.pack(fill="x", padx=S(14), pady=(S(10), S(4)))
            tk.Label(self.header, text="▍" + title.upper(), font=theme.mono(9, "bold"),
                     bg=theme.SURFACE, fg=theme.ACCENT).pack(side="left")
        self.body = tk.Frame(self, bg=theme.SURFACE)
        self.body.pack(fill="both", expand=True, padx=S(14), pady=(0, S(12)))


class PlaceholderEntry(tk.Entry):
    """Entry with grey placeholder text and an optional masked (secret) mode."""

    def __init__(self, master, placeholder="", font=None, **kw):
        super().__init__(master, bg=theme.SURFACE_2, fg=theme.TEXT, insertbackground=theme.ACCENT,
                         relief="flat", font=font or theme.mono(12), highlightthickness=S(1),
                         highlightbackground=theme.BORDER, highlightcolor=theme.ACCENT,
                         disabledbackground=theme.SURFACE_2, **kw)
        self._placeholder = placeholder
        self._secret = False
        self._showing = False
        self.reveal = False
        self.bind("<FocusIn>", self._focus_in, add="+")
        self.bind("<FocusOut>", self._focus_out, add="+")
        self._show_placeholder()

    def value(self) -> str:
        return "" if self._showing else self.get()

    def set_placeholder(self, text: str):
        self._placeholder = text
        if self._showing or not self.get():
            self._show_placeholder()

    def set_secret(self, secret: bool):
        self._secret = secret
        self.reveal = False
        self._apply_mask()

    def toggle_reveal(self):
        self.reveal = not self.reveal
        self._apply_mask()

    def clear(self):
        self.delete(0, "end")
        self._showing = False
        if self.focus_get() is not self:
            self._show_placeholder()

    def _apply_mask(self):
        masked = self._secret and not self.reveal and not self._showing
        self.configure(show="•" if masked else "")

    def _show_placeholder(self):
        self.delete(0, "end")
        self.insert(0, self._placeholder)
        self._showing = True
        self.configure(fg=theme.DIM)
        self._apply_mask()

    def _focus_in(self, _e):
        if self._showing:
            self.delete(0, "end")
            self._showing = False
            self.configure(fg=theme.TEXT)
            self._apply_mask()

    def _focus_out(self, _e):
        if not self.get():
            self._show_placeholder()


class Toggle(tk.Canvas):
    """iOS-style on/off switch."""

    def __init__(self, master, command=None, on_color=theme.WARN, value=False):
        w, h = S(44), S(22)
        super().__init__(master, width=w, height=h, bg=theme.SURFACE, highlightthickness=0, cursor="hand2")
        self._width, self._height, self.value, self._on_color, self._command = w, h, value, on_color, command
        self.bind("<Button-1>", lambda e: self.set(not self.value, notify=True))
        self._draw()

    def set(self, value: bool, notify=False):
        self.value = value
        self._draw()
        if notify and self._command:
            self._command(value)

    def _draw(self):
        self.delete("all")
        w, h, r = self._width, self._height, self._height / 2
        color = self._on_color if self.value else theme.DIM
        self.create_oval(0, 0, h, h, fill=color, outline=color)
        self.create_oval(w - h, 0, w, h, fill=color, outline=color)
        self.create_rectangle(r, 0, w - r, h, fill=color, outline=color)
        x = w - r if self.value else r
        self.create_oval(x - r + 3, 3, x + r - 3, h - 3, fill="#ffffff", outline="")


class StrengthMeter(tk.Canvas):
    """Five-segment live password strength bar."""

    COLORS = (theme.DANGER, "#ff7043", theme.WARN, "#9ccc65", theme.GREEN)

    def __init__(self, master, width=260):
        super().__init__(master, width=S(width), height=S(6), bg=theme.SURFACE, highlightthickness=0)
        self._width = S(width)
        self.set(-1)

    def set(self, score: int):
        self.delete("all")
        gap, n = S(4), 5
        seg = (self._width - gap * (n - 1)) / n
        for i in range(n):
            x = i * (seg + gap)
            color = self.COLORS[score] if 0 <= i <= score else theme.BORDER
            self.create_rectangle(x, 0, x + seg, S(6), fill=color, outline="")


class ScanVisual(tk.Canvas):
    """Radar sweep while idle / scanning, then morphs into an animated threat gauge."""

    TRAIL = 30
    FRAME_MS = 30

    def __init__(self, master, size=300):
        self.size = S(size)
        super().__init__(master, width=self.size, height=self.size + S(40),
                         bg=theme.SURFACE, highlightthickness=0)
        self.cx = self.cy = self.size / 2
        self.r = self.size / 2 - S(12)
        self.mode = "idle"
        self.angle = 90.0
        self.frame = 0
        self.blips: list[list] = []
        self.pings: list[list] = []
        self.value = 0.0
        self.target_value = 0.0
        self.result_color = theme.GREEN
        self._build_radar()
        self._build_gauge()
        self.set_idle()
        self._tick()

    # ---- construction -------------------------------------------------
    def _build_radar(self):
        cx, cy, r = self.cx, self.cy, self.r
        ring = blend(theme.GREEN, theme.SURFACE, 0.78)
        self.create_oval(cx - r, cy - r, cx + r, cy + r, fill=blend(theme.GREEN, theme.SURFACE, 0.95),
                         outline=blend(theme.GREEN, theme.SURFACE, 0.5), width=S(2), tags="radar")
        for f in (0.25, 0.5, 0.75):
            self.create_oval(cx - r * f, cy - r * f, cx + r * f, cy + r * f, outline=ring, tags="radar")
        self.create_line(cx - r, cy, cx + r, cy, fill=ring, tags="radar")
        self.create_line(cx, cy - r, cx, cy + r, fill=ring, tags="radar")
        for deg in range(0, 360, 10):
            a = math.radians(deg)
            inner = r - (S(8) if deg % 30 == 0 else S(4))
            self.create_line(cx + inner * math.cos(a), cy - inner * math.sin(a),
                             cx + r * math.cos(a), cy - r * math.sin(a),
                             fill=blend(theme.GREEN, theme.SURFACE, 0.55), tags="radar")
        self.sweep = []
        for i in range(self.TRAIL):
            t = i / self.TRAIL
            self.sweep.append(self.create_line(cx, cy, cx, cy - r, width=S(3) if i == 0 else S(2),
                                               fill=blend(theme.GREEN, theme.SURFACE, 0.15 + t * 0.85),
                                               tags=("radar", "sweep")))
        for item in reversed(self.sweep):
            self.tag_raise(item)
        self.create_oval(cx - S(3), cy - S(3), cx + S(3), cy + S(3), fill=theme.GREEN, outline="", tags="radar")
        self.radar_title = self.create_text(cx, self.size + S(12), text="", font=theme.mono(10, "bold"),
                                            fill=theme.GREEN, tags="radar")
        self.radar_sub = self.create_text(cx, self.size + S(30), text="", font=theme.mono(8),
                                          fill=theme.MUTED, tags="radar")

    def _gauge_angle(self, value: float) -> float:
        return 210 - 2.4 * value  # 0 -> 210deg (lower-left), 100 -> -30deg (lower-right)

    def _build_gauge(self):
        cx, cy = self.cx, self.cy + S(8)
        self.gcy = cy
        r_band = self.r - S(2)
        r_val = self.r - S(22)
        bb = lambda rad: (cx - rad, cy - rad, cx + rad, cy + rad)

        for level in (RiskLevel.SAFE, RiskLevel.CAUTION, RiskLevel.EXPOSED, RiskLevel.CRITICAL):
            lo, hi = level.band
            self.create_arc(*bb(r_band), start=self._gauge_angle(hi) + 1, extent=2.4 * (hi - lo) - 2,
                            style="arc", width=S(5), outline=blend(level.color, theme.SURFACE, 0.35), tags="gauge")
        self.create_arc(*bb(r_val), start=-30, extent=240, style="arc", width=S(16),
                        outline=theme.RAISED, tags="gauge")
        self.value_arc = self.create_arc(*bb(r_val), start=210, extent=0, style="arc", width=S(16),
                                         outline=theme.GREEN, tags="gauge")
        for v in range(0, 101, 5):
            a = math.radians(self._gauge_angle(v))
            r1 = r_val - S(14)
            r2 = r1 - (S(7) if v % 25 == 0 else S(3))
            self.create_line(cx + r1 * math.cos(a), cy - r1 * math.sin(a), cx + r2 * math.cos(a),
                             cy - r2 * math.sin(a), fill=theme.DIM if v % 25 else theme.MUTED, tags="gauge")
        self.r_val = r_val
        self.knob = self.create_oval(0, 0, 0, 0, fill=theme.GREEN, outline=theme.TEXT, width=S(2), tags="gauge")
        self.create_text(cx, cy - self.r * 0.3, text="THREAT SCORE", font=theme.mono(8, "bold"),
                         fill=theme.MUTED, tags="gauge")
        self.score_text = self.create_text(cx, cy, text="0", font=theme.mono(34, "bold"),
                                           fill=theme.TEXT, tags="gauge")
        self.create_text(cx, cy + self.r * 0.3, text="/ 100", font=theme.mono(9), fill=theme.MUTED, tags="gauge")
        self.verdict_text = self.create_text(cx, self.size + S(12), text="", font=theme.mono(15, "bold"),
                                             fill=theme.GREEN, tags="gauge")
        self.status_text = self.create_text(cx, self.size + S(32), text="", font=theme.ui(9),
                                            fill=theme.MUTED, tags="gauge")

    # ---- public API ---------------------------------------------------
    def set_idle(self, subtitle="awaiting target"):
        self.mode = "idle"
        self._show("radar")
        self.itemconfigure(self.radar_title, text="◉ STANDBY", fill=theme.MUTED)
        self.itemconfigure(self.radar_sub, text=subtitle)

    def set_scanning(self, subtitle: str):
        self.mode = "scan"
        self._show("radar")
        self.itemconfigure(self.radar_sub, text=subtitle)
        self.pings.clear()

    def set_result(self, result: ScanResult):
        self.mode = "result"
        self._show("gauge")
        level = result.risk
        self.result_color = level.color
        self.value = 0.0
        self.target_value = 0.0 if level is RiskLevel.ERROR else float(result.score)
        self.itemconfigure(self.value_arc, outline=level.color)
        self.itemconfigure(self.knob, fill=level.color)
        self.itemconfigure(self.verdict_text, text=f"■ {level.label}", fill=level.color)
        status = result.status if len(result.status) < 34 else result.status[:32] + "…"
        self.itemconfigure(self.status_text, text=status)
        self.itemconfigure(self.score_text, text="--" if level is RiskLevel.ERROR else "0",
                           fill=theme.MUTED if level is RiskLevel.ERROR else theme.TEXT)
        self._draw_value()

    # ---- animation ----------------------------------------------------
    def _show(self, tag: str):
        self.itemconfigure("radar", state="normal" if tag == "radar" else "hidden")
        self.itemconfigure("gauge", state="normal" if tag == "gauge" else "hidden")
        for _, item, _ in self.blips:
            self.delete(item)
        self.blips.clear()
        for item, _ in self.pings:
            self.delete(item)
        self.pings.clear()

    def _tick(self):
        self.frame += 1
        if self.mode in ("idle", "scan"):
            self._animate_radar()
        else:
            self._animate_gauge()
        self.after(self.FRAME_MS, self._tick)

    def _animate_radar(self):
        scanning = self.mode == "scan"
        self.angle = (self.angle - (7.0 if scanning else 1.8)) % 360  # clockwise
        spacing = 1.7 if scanning else 1.1
        cx, cy, r = self.cx, self.cy, self.r
        for i, item in enumerate(self.sweep):
            a = math.radians(self.angle + i * spacing)
            self.coords(item, cx, cy, cx + r * math.cos(a), cy - r * math.sin(a))

        if random.random() < (0.22 if scanning else 0.025):
            a = math.radians(self.angle + random.uniform(0, 6))
            d = random.uniform(0.15, 0.92) * r
            x, y = cx + d * math.cos(a), cy - d * math.sin(a)
            size = random.uniform(S(2.5), S(4.5))
            color = theme.DANGER if scanning and random.random() < 0.15 else theme.GREEN
            item = self.create_oval(x - size, y - size, x + size, y + size, fill=color, outline="", tags="radar")
            self.blips.append([1.0, item, color])
        for blip in self.blips[:]:
            blip[0] -= 0.025
            if blip[0] <= 0:
                self.delete(blip[1])
                self.blips.remove(blip)
            else:
                self.itemconfigure(blip[1], fill=blend(blip[2], theme.SURFACE, 1 - blip[0]))

        if scanning:
            if self.frame % 28 == 0:
                self.pings.append([self.create_oval(cx, cy, cx, cy, outline=theme.ACCENT, width=S(2), tags="radar"), 0.0])
            for ping in self.pings[:]:
                ping[1] += 0.03
                pr = r * ping[1]
                if ping[1] >= 1:
                    self.delete(ping[0])
                    self.pings.remove(ping)
                else:
                    self.coords(ping[0], cx - pr, cy - pr, cx + pr, cy + pr)
                    self.itemconfigure(ping[0], outline=blend(theme.ACCENT, theme.SURFACE, ping[1]))
            dots = "." * (self.frame // 8 % 4)
            flicker = theme.ACCENT if self.frame % 16 < 12 else theme.GREEN
            self.itemconfigure(self.radar_title, text=f"◉ SCANNING{dots:<3}", fill=flicker)

    def _animate_gauge(self):
        if abs(self.target_value - self.value) < 0.05:
            return
        self.value += (self.target_value - self.value) * 0.09 + (0.1 if self.target_value > self.value else 0)
        self.value = min(self.value, self.target_value)
        self._draw_value()
        self.itemconfigure(self.score_text, text=str(round(self.value)))

    def _draw_value(self):
        """Grow the value arc and move the knob to its tip."""
        a = math.radians(self._gauge_angle(self.value))
        x, y = self.cx + self.r_val * math.cos(a), self.gcy - self.r_val * math.sin(a)
        k = S(9)
        self.coords(self.knob, x - k, y - k, x + k, y + k)
        self.itemconfigure(self.value_arc, extent=-2.4 * self.value if self.value > 0.5 else -0.1)


class MatrixRain(tk.Canvas):
    """Falling-glyph 'digital rain'. Glyphs are kept below the item named in `below`."""

    GLYPHS = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789$#@%&<>/\\=+*"
    FRAME_MS = 45

    def __init__(self, master, **kw):
        super().__init__(master, bg=theme.BG, highlightthickness=0, **kw)
        self.font = tkfont.Font(family=theme.MONO, size=11, weight="bold")
        self.cell = max(self.font.measure("W"), self.font.metrics("linespace")) + 2
        trail = 22
        self.palette = ["#f0fff8"] + [blend(theme.GREEN, theme.BG, i / trail) for i in range(trail)]
        self.below = None
        self.columns: list[list] = []
        self.glyphs: list[list] = []  # [item, age]
        self.running = False

    def start(self):
        self.running = True
        self.update_idletasks()
        cols = max(1, self.winfo_width() // self.cell)
        rows = max(1, self.winfo_height() // self.cell)
        self.rows = rows
        self.columns = [[random.uniform(-rows, rows * 0.6), random.uniform(0.35, 0.9)] for _ in range(cols)]
        self._tick()

    def stop(self):
        self.running = False

    def _tick(self):
        if not self.running:
            return
        for col, state in enumerate(self.columns):
            before = int(state[0])
            state[0] += state[1]
            if int(state[0]) != before and 0 <= int(state[0]) < self.rows:
                x = col * self.cell + self.cell / 2
                y = int(state[0]) * self.cell + self.cell / 2
                item = self.create_text(x, y, text=random.choice(self.GLYPHS), fill=self.palette[0], font=self.font)
                if self.below is not None:
                    self.tag_lower(item, self.below)
                self.glyphs.append([item, 0])
            if state[0] > self.rows + random.randint(0, 20):
                state[0] = random.uniform(-10, 0)
                state[1] = random.uniform(0.35, 0.9)

        alive = []
        for glyph in self.glyphs:
            glyph[1] += 1
            if glyph[1] >= len(self.palette):
                self.delete(glyph[0])
                continue
            self.itemconfigure(glyph[0], fill=self.palette[glyph[1]])
            if random.random() < 0.03:
                self.itemconfigure(glyph[0], text=random.choice(self.GLYPHS))
            alive.append(glyph)
        self.glyphs = alive
        self.after(self.FRAME_MS, self._tick)


class DataBus(tk.Canvas):
    """Thin line under the header with a light pulse travelling along it."""

    def __init__(self, master):
        super().__init__(master, height=S(2), bg=theme.BORDER, highlightthickness=0)
        self.pos = 0.0
        self.color = theme.ACCENT
        self.segment = self.create_rectangle(0, 0, 0, S(2), fill=theme.ACCENT, outline="")
        self.glow = self.create_rectangle(0, 0, 0, S(2), fill=blend(theme.ACCENT, theme.BORDER, 0.6), outline="")
        self._tick()

    def alert(self, color: str, duration_ms=1800):
        self.color = color
        self.after(duration_ms, lambda: setattr(self, "color", theme.ACCENT))

    def _tick(self):
        w = max(self.winfo_width(), 1)
        self.pos = (self.pos + 0.006) % 1.3
        x = self.pos * w - 0.15 * w
        self.coords(self.glow, x - S(120), 0, x + S(160), S(2))
        self.coords(self.segment, x, 0, x + S(80), S(2))
        self.itemconfigure(self.segment, fill=self.color)
        self.itemconfigure(self.glow, fill=blend(self.color, theme.BORDER, 0.6))
        self.after(16, self._tick)
