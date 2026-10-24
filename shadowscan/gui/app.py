"""ShadowScan main window."""

from __future__ import annotations

import json
import os
import queue
import random
import sys
import threading
import time
import tkinter as tk
import webbrowser
from dataclasses import dataclass
from tkinter import filedialog, messagebox, ttk

from .. import APP_NAME, __version__, config, strength
from ..engine import ScanEngine
from ..models import RiskLevel, ScanResult
from ..net import ping
from ..providers.abuseipdb import ENV_KEY as ABUSE_KEY
from ..targets import make_target
from . import theme
from .splash import Splash
from .theme import S, blend
from .widgets import (Card, DataBus, FlatButton, NavItem, PlaceholderEntry, ScanVisual,
                      StrengthMeter, Toggle)

MIN_SCAN_SECONDS = 1.8  # keep the radar on screen long enough to be seen


@dataclass(frozen=True)
class Module:
    kind: str
    title: str
    icon: str
    source: str
    description: str
    placeholder: str
    intro: tuple[str, ...]


MODULES = (
    Module("email", "Email Breach Check", "✉", "XposedOrNot",
           "Checks whether an email address appears in publicly disclosed data breaches.",
           "name@example.com",
           ("Enter an email address and press SCAN (or Enter).",
            "ShadowScan queries XposedOrNot's index of public breaches and pulls",
            "breach analytics: which sites leaked it, when, and what data was exposed.")),
    Module("password", "Password Exposure", "✱", "XposedOrNot · k-anonymity",
           "Checks if a password has appeared in leaked password dumps - without ever sending it.",
           "type a password to test",
           ("Your password NEVER leaves this computer.",
            "1. It is hashed locally with Keccak-512 (128 hex characters).",
            "2. Only the first 10 hex characters are sent to the API.",
            "3. Thousands of different passwords share that prefix, so the",
            "   server cannot tell which one you typed (k-anonymity).",
            "The strength meter below the input is calculated fully offline.")),
    Module("username", "Username Exposure", "☺", "LeakCheck",
           "Searches breach databases for a username or gamer tag.",
           "e.g. johnsmith42",
           ("Enter a username and press SCAN.",
            "LeakCheck's public API returns breach source names and the kinds of",
            "fields leaked - never the leaked data itself.")),
    Module("phone", "Phone Exposure", "☎", "LeakCheck",
           "Checks if a phone number appears in breach databases.",
           "e.g. +91 98765 43210",
           ("Enter a phone number including the country code.",
            "Spaces, dashes, brackets and + are stripped automatically.",
            "Note: phone coverage in breach data is thinner than email coverage.")),
    Module("ip", "IP Reputation", "⌖", "AbuseIPDB",
           "Looks up abuse reports for an IPv4 / IPv6 address (spam, brute-force, scanning...).",
           "e.g. 185.220.101.1",
           ("Enter an IP address and press SCAN.",
            "This checks ABUSE REPORTS submitted by network admins worldwide,",
            "not breach exposure. Requires a free AbuseIPDB key (see DIAGNOSTICS).")),
    Module("domain", "Domain Threat Intel", "◎", "AlienVault OTX",
           "Checks whether a domain is referenced in open threat-intelligence feeds.",
           "e.g. example.com",
           ("Enter a domain (pasting a full URL works too) and press SCAN.",
            "AlienVault OTX pulses are community threat reports covering phishing,",
            "malware hosting and command-and-control infrastructure.")),
)

LOG_COLORS = {"info": theme.GREEN, "sys": theme.ACCENT, "warn": theme.WARN, "err": theme.DANGER}
SCRAMBLE = "█▓▒░#$%&@*+=<>/\\|"


class ShadowScanApp(tk.Tk):
    def __init__(self, splash: bool = True):
        theme.enable_dpi_awareness()
        super().__init__()
        theme.init(self)
        config.load_env()

        self.title(f"{APP_NAME} — Breach Intelligence Console")
        self.configure(bg=theme.BG)
        self.compact = self.winfo_screenheight() < S(860)
        self.geometry(f"{S(1280)}x{min(S(790), self.winfo_screenheight() - S(60))}")
        self.minsize(S(1100), S(640))
        if sys.platform == "win32":
            self.state("zoomed")
        self._set_icon()
        self._style_ttk()

        self.engine = ScanEngine()
        self.history: list[ScanResult] = []
        self.events: queue.Queue = queue.Queue()
        self.scanning = False
        self.started = time.time()
        self.module = MODULES[0]
        self.current_result: ScanResult | None = None
        self.pages: dict[str, tk.Frame] = {}
        self.nav: dict[str, NavItem] = {}
        self._reveal_job = None

        self._build_layout()
        self.show_module(MODULES[0])
        self._bind_keys()
        self._poll_events()
        self._tick_clock()
        self._glitch_logo()
        self.log("sys", f"{APP_NAME} v{__version__} online · {len(self.engine.providers)} providers loaded")
        if not self._abuse_key():
            self.log("warn", "AbuseIPDB key not set - IP Reputation needs one (see DIAGNOSTICS)")

        if splash:
            s = Splash(self, on_done=lambda: self.entry.focus_set())
            s.place(x=0, y=0, relwidth=1, relheight=1)
        else:
            self.after(100, self.entry.focus_set)

    # ================================================================ setup
    def _set_icon(self):
        size = 32
        img = tk.PhotoImage(width=size, height=size)
        c = (size - 1) / 2
        for y in range(size):
            row = []
            for x in range(size):
                d = ((x - c) ** 2 + (y - c) ** 2) ** 0.5
                if d > 15.5:
                    row.append(theme.BG)
                elif d > 13.5:
                    row.append(theme.ACCENT)
                elif abs(x - c) < 1 or abs(y - c) < 1:
                    row.append(blend(theme.GREEN, theme.BG, 0.5))
                elif x > c and y < c and abs((x - c) - (c - y)) < 2.5:
                    row.append(theme.GREEN)
                else:
                    row.append("#04140f")
            img.put("{" + " ".join(row) + "}", to=(0, y))
        self._icon = img
        self.iconphoto(True, img)

    def _style_ttk(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background=theme.SURFACE, fieldbackground=theme.SURFACE,
                        foreground=theme.TEXT, borderwidth=0, rowheight=S(30), font=theme.ui(10))
        style.configure("Treeview.Heading", background=theme.SURFACE_2, foreground=theme.MUTED,
                        relief="flat", font=theme.mono(9, "bold"), padding=(S(8), S(6)))
        style.map("Treeview", background=[("selected", theme.RAISED)], foreground=[("selected", theme.ACCENT)])
        style.map("Treeview.Heading", background=[("active", theme.RAISED)])
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        for orient in ("Vertical", "Horizontal"):
            style.configure(f"{orient}.TScrollbar", background=theme.RAISED, troughcolor=theme.SURFACE,
                            bordercolor=theme.SURFACE, arrowcolor=theme.MUTED, lightcolor=theme.RAISED,
                            darkcolor=theme.RAISED, gripcount=0, arrowsize=S(12))
            style.map(f"{orient}.TScrollbar", background=[("active", theme.DIM)])

    def _build_layout(self):
        self._build_header()
        self.bus = DataBus(self)
        self.bus.pack(fill="x")
        self._build_statusbar()

        body = tk.Frame(self, bg=theme.BG)
        body.pack(fill="both", expand=True)
        self._build_sidebar(body)

        self.content = tk.Frame(body, bg=theme.BG)
        self.content.pack(side="left", fill="both", expand=True, padx=S(18), pady=S(16))
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)
        self.pages["scan"] = self._build_scan_page()
        self.pages["history"] = self._build_history_page()
        self.pages["diagnostics"] = self._build_diagnostics_page()
        self.pages["about"] = self._build_about_page()
        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")

    def _build_header(self):
        header = tk.Frame(self, bg=theme.SURFACE, height=S(58))
        header.pack(fill="x")
        header.pack_propagate(False)
        left = tk.Frame(header, bg=theme.SURFACE)
        left.pack(side="left", padx=S(20))
        self.logo = tk.Label(left, text="◢◤ SHADOWSCAN", font=theme.mono(17, "bold"),
                             bg=theme.SURFACE, fg=theme.ACCENT)
        self.logo.pack(side="left")
        tk.Label(left, text="  BREACH INTELLIGENCE CONSOLE", font=theme.mono(9),
                 bg=theme.SURFACE, fg=theme.MUTED).pack(side="left", pady=(S(6), 0))

        right = tk.Frame(header, bg=theme.SURFACE)
        right.pack(side="right", padx=S(20))
        self.clock = tk.Label(right, font=theme.mono(11), bg=theme.SURFACE, fg=theme.TEXT)
        self.clock.pack(side="right")
        self.mode_pill = tk.Label(right, font=theme.mono(9, "bold"), padx=S(10), pady=S(3))
        self.mode_pill.pack(side="right", padx=S(16))
        self._update_mode_pill()

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=theme.SURFACE, height=S(28))
        bar.pack(side="bottom", fill="x")
        bar.pack_propagate(False)
        self.status_left = tk.Label(bar, text="", font=theme.mono(8), bg=theme.SURFACE, fg=theme.MUTED)
        self.status_left.pack(side="left", padx=S(14))
        self.status_right = tk.Label(bar, text="", font=theme.mono(8), bg=theme.SURFACE, fg=theme.MUTED)
        self.status_right.pack(side="right", padx=S(14))
        self.set_status("Ready.")

    def _build_sidebar(self, parent):
        side = tk.Frame(parent, bg=theme.SURFACE, width=S(230))
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Frame(side, bg=theme.BORDER, width=1).pack(side="right", fill="y")

        def section(text):
            tk.Label(side, text=text, font=theme.mono(8, "bold"), bg=theme.SURFACE, fg=theme.DIM,
                     anchor="w").pack(fill="x", padx=S(18), pady=(S(18), S(6)))

        section("SCAN MODULES")
        for i, mod in enumerate(MODULES, start=1):
            item = NavItem(side, mod.icon, mod.title, lambda m=mod: self.show_module(m), f"^{i}")
            item.pack(fill="x")
            self.nav[mod.kind] = item
        section("SYSTEM")
        for key, icon, label, hint in (("history", "☰", "Scan History", "^H"),
                                       ("diagnostics", "⚙", "Diagnostics", "^D"),
                                       ("about", "ⓘ", "About", "")):
            item = NavItem(side, icon, label, lambda k=key: self.show_page(k), hint)
            item.pack(fill="x")
            self.nav[key] = item

        stats = tk.Frame(side, bg=theme.SURFACE)
        stats.pack(side="bottom", fill="x", padx=S(18), pady=S(16))
        tk.Label(stats, text="SESSION", font=theme.mono(8, "bold"), bg=theme.SURFACE, fg=theme.DIM,
                 anchor="w").pack(fill="x")
        self.side_stats = tk.Label(stats, text="", font=theme.mono(9), bg=theme.SURFACE, fg=theme.MUTED,
                                   justify="left", anchor="w")
        self.side_stats.pack(fill="x", pady=(S(4), 0))
        self._update_stats()

    # ------------------------------------------------------------ scan page
    def _build_scan_page(self):
        page = tk.Frame(self.content, bg=theme.BG)
        page.grid_columnconfigure(1, weight=1)
        page.grid_rowconfigure(2, weight=1)

        head = tk.Frame(page, bg=theme.BG)
        head.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, S(12)))
        self.mod_icon = tk.Label(head, font=theme.symbol(26), bg=theme.BG, fg=theme.ACCENT, width=2)
        self.mod_icon.pack(side="left", padx=(0, S(10)))
        titles = tk.Frame(head, bg=theme.BG)
        titles.pack(side="left", fill="x", expand=True)
        self.mod_title = tk.Label(titles, font=theme.ui(18, "bold"), bg=theme.BG, fg=theme.TEXT, anchor="w")
        self.mod_title.pack(fill="x")
        self.mod_desc = tk.Label(titles, font=theme.ui(10), bg=theme.BG, fg=theme.MUTED, anchor="w")
        self.mod_desc.pack(fill="x")
        chip = tk.Frame(head, bg=theme.BG, highlightthickness=1, highlightbackground=theme.BORDER)
        chip.pack(side="right")
        tk.Label(chip, text="SOURCE", font=theme.mono(7, "bold"), bg=theme.BG, fg=theme.DIM).pack(
            side="left", padx=(S(10), S(6)), pady=S(6))
        self.mod_source = tk.Label(chip, font=theme.mono(9, "bold"), bg=theme.BG, fg=theme.GREEN)
        self.mod_source.pack(side="left", padx=(0, S(10)))

        # input row
        inp = Card(page)
        inp.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, S(12)))
        row = tk.Frame(inp.body, bg=theme.SURFACE)
        row.pack(fill="x", pady=(S(12), 0))
        tk.Label(row, text="›", font=theme.mono(18, "bold"), bg=theme.SURFACE, fg=theme.GREEN).pack(
            side="left", padx=(0, S(8)))
        self.entry = PlaceholderEntry(row)
        self.entry.pack(side="left", fill="x", expand=True, ipady=S(8))
        self.entry.bind("<Return>", lambda e: self.start_scan())
        self.entry.bind("<KeyRelease>", lambda e: self._update_strength())
        self.eye = FlatButton(row, "SHOW", self._toggle_reveal, bg=theme.SURFACE_2, fg=theme.MUTED,
                              font=theme.mono(8, "bold"), padx=10, pady=10)
        self.scan_btn = FlatButton(row, "▶  SCAN", self.start_scan, bg=theme.ACCENT, fg="#00141a",
                                   hover_bg="#7af3ff", font=theme.mono(11, "bold"), padx=26, pady=9)
        self.scan_btn.pack(side="right", padx=(S(10), 0))

        under = tk.Frame(inp.body, bg=theme.SURFACE)
        under.pack(fill="x", pady=(S(8), 0))
        self.hint = tk.Label(under, text="", font=theme.ui(9), bg=theme.SURFACE, fg=theme.MUTED, anchor="w")
        self.hint.pack(side="left")
        self.strength_box = tk.Frame(under, bg=theme.SURFACE)
        self.strength_label = tk.Label(self.strength_box, text="", font=theme.mono(8), bg=theme.SURFACE,
                                       fg=theme.MUTED)
        self.strength_label.pack(side="right", padx=(S(10), 0))
        self.strength = StrengthMeter(self.strength_box, width=200)
        self.strength.pack(side="right")

        # visual + findings
        vis_card = Card(page, "Threat Radar")
        vis_card.grid(row=2, column=0, sticky="nsew", padx=(0, S(12)))
        self.visual = ScanVisual(vis_card.body, size=220 if self.compact else 270)
        self.visual.pack(expand=True, pady=S(6))

        find_card = Card(page, "Findings")
        find_card.grid(row=2, column=1, sticky="nsew")
        actions = tk.Frame(find_card.header, bg=theme.SURFACE)
        actions.pack(side="right")
        FlatButton(actions, "COPY", self.copy_findings, bg=theme.SURFACE_2, fg=theme.MUTED,
                   font=theme.mono(8, "bold"), padx=10, pady=3).pack(side="left", padx=S(4))
        FlatButton(actions, "SAVE REPORT", lambda: self.export_report("txt", [self.current_result] if self.current_result else []),
                   bg=theme.SURFACE_2, fg=theme.MUTED, font=theme.mono(8, "bold"), padx=10, pady=3).pack(side="left")
        self.findings = self._scrolled_text(find_card.body, bg=theme.SURFACE, font=theme.mono(10), padx=S(4))
        f = self.findings
        f.tag_configure("muted", foreground=theme.MUTED)
        f.tag_configure("dim", foreground=theme.DIM)
        f.tag_configure("accent", foreground=theme.ACCENT)
        f.tag_configure("warn", foreground=theme.WARN)
        f.tag_configure("ok", foreground=theme.GREEN)
        f.tag_configure("scramble", foreground=theme.DIM)
        f.tag_configure("heading", foreground=theme.ACCENT, font=theme.mono(10, "bold"), spacing1=S(6))
        f.tag_configure("title", font=theme.mono(15, "bold"), spacing3=S(2))
        for level in RiskLevel:
            f.tag_configure(level.name, foreground=level.color, font=theme.mono(15, "bold"))

        log_card = Card(page, "Activity Log")
        log_card.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(S(12), 0))
        self.log_text = self._scrolled_text(log_card.body, bg=theme.LOG_BG, font=theme.mono(9), height=4 if self.compact else 6,
                                            padx=S(8), pady=S(6))
        self.log_text.tag_configure("time", foreground=theme.DIM)
        for name, color in LOG_COLORS.items():
            self.log_text.tag_configure(name, foreground=color)
        return page

    def _scrolled_text(self, parent, **kw) -> tk.Text:
        frame = tk.Frame(parent, bg=kw.get("bg", theme.SURFACE))
        frame.pack(fill="both", expand=True)
        text = tk.Text(frame, relief="flat", wrap="word", fg=theme.TEXT, highlightthickness=0,
                       insertbackground=theme.ACCENT, selectbackground=theme.RAISED, cursor="arrow",
                       borderwidth=0, **kw)
        bar = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=bar.set, state="disabled")
        bar.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        return text

    # --------------------------------------------------------- history page
    def _build_history_page(self):
        page = tk.Frame(self.content, bg=theme.BG)
        self._page_title(page, "☰", "Scan History", "Every lookup made this session. Double-click a row to reopen it.")

        tiles = tk.Frame(page, bg=theme.BG)
        tiles.pack(fill="x", pady=(0, S(12)))
        self.tiles = {}
        for i, (key, label, color) in enumerate((
                ("total", "TOTAL SCANS", theme.ACCENT), ("CRITICAL", "CRITICAL", RiskLevel.CRITICAL.color),
                ("EXPOSED", "EXPOSED", RiskLevel.EXPOSED.color), ("CAUTION", "CAUTION", RiskLevel.CAUTION.color),
                ("SAFE", "SAFE", RiskLevel.SAFE.color))):
            tile = tk.Frame(tiles, bg=theme.SURFACE, highlightthickness=1, highlightbackground=theme.BORDER)
            tile.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else S(10), 0))
            tiles.grid_columnconfigure(i, weight=1, uniform="tiles")
            tk.Frame(tile, bg=color, height=S(3)).pack(fill="x")
            num = tk.Label(tile, text="0", font=theme.mono(24, "bold"), bg=theme.SURFACE, fg=color)
            num.pack(anchor="w", padx=S(14), pady=(S(8), 0))
            tk.Label(tile, text=label, font=theme.mono(8, "bold"), bg=theme.SURFACE, fg=theme.MUTED).pack(
                anchor="w", padx=S(14), pady=(0, S(10)))
            self.tiles[key] = num

        card = Card(page, "Results")
        card.pack(fill="both", expand=True)
        buttons = tk.Frame(card.header, bg=theme.SURFACE)
        buttons.pack(side="right")
        for text, cmd in (("OPEN", self.open_selected),
                          ("EXPORT .TXT", lambda: self.export_report("txt", self.history)),
                          ("EXPORT .JSON", lambda: self.export_report("json", self.history)),
                          ("CLEAR", self.clear_history)):
            FlatButton(buttons, text, cmd, bg=theme.SURFACE_2, fg=theme.MUTED, font=theme.mono(8, "bold"),
                       padx=10, pady=3).pack(side="left", padx=(S(6), 0))

        cols = ("time", "module", "target", "verdict", "score", "source", "duration")
        widths = (90, 150, 220, 100, 70, 200, 80)
        self.tree = ttk.Treeview(card.body, columns=cols, show="headings", selectmode="browse")
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col.upper(), anchor="w")
            self.tree.column(col, width=S(w), anchor="w", stretch=col in ("target", "source"))
        for level in RiskLevel:
            self.tree.tag_configure(level.name, foreground=level.color)
        bar = ttk.Scrollbar(card.body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda e: self.open_selected())
        self.empty_history = tk.Label(card.body, text="No scans yet - run one from a scan module.",
                                      font=theme.ui(10), bg=theme.SURFACE, fg=theme.DIM)
        self.empty_history.place(relx=0.5, rely=0.45, anchor="center")
        return page

    # ----------------------------------------------------- diagnostics page
    def _build_diagnostics_page(self):
        page = tk.Frame(self.content, bg=theme.BG)
        self._page_title(page, "⚙", "Diagnostics", "API keys, offline demo mode and live provider health checks.")
        top = tk.Frame(page, bg=theme.BG)
        top.pack(fill="x", pady=(0, S(12)))
        top.grid_columnconfigure(0, weight=1, uniform="d")
        top.grid_columnconfigure(1, weight=1, uniform="d")

        keys = Card(top, "AbuseIPDB API Key")
        keys.grid(row=0, column=0, sticky="nsew", padx=(0, S(12)))
        tk.Label(keys.body, text="Needed for IP Reputation only. Free: 1,000 checks/day.\n"
                                 "Saved to the local .env file (never inside the source code).",
                 font=theme.ui(9), bg=theme.SURFACE, fg=theme.MUTED, justify="left").pack(anchor="w")
        row = tk.Frame(keys.body, bg=theme.SURFACE)
        row.pack(fill="x", pady=(S(10), S(6)))
        self.key_entry = PlaceholderEntry(row, placeholder="paste API key", font=theme.mono(10))
        self.key_entry.set_secret(True)
        self.key_entry.pack(side="left", fill="x", expand=True, ipady=S(5))
        FlatButton(row, "SAVE", self.save_key, bg=theme.ACCENT, fg="#00141a", hover_bg="#7af3ff",
                   font=theme.mono(9, "bold")).pack(side="left", padx=(S(8), 0))
        status_row = tk.Frame(keys.body, bg=theme.SURFACE)
        status_row.pack(fill="x")
        self.key_status = tk.Label(status_row, font=theme.mono(9), bg=theme.SURFACE)
        self.key_status.pack(side="left")
        link = tk.Label(status_row, text="get a free key ↗", font=theme.mono(9, "underline"),
                        bg=theme.SURFACE, fg=theme.ACCENT, cursor="hand2")
        link.pack(side="right")
        link.bind("<Button-1>", lambda e: webbrowser.open("https://www.abuseipdb.com/account/api"))
        self._update_key_status()

        demo = Card(top, "Offline Demo Mode")
        demo.grid(row=0, column=1, sticky="nsew")
        drow = tk.Frame(demo.body, bg=theme.SURFACE)
        drow.pack(fill="x")
        tk.Label(drow, text="Use the built-in sample dataset instead of live APIs.\n"
                            "Handy when presenting without internet. Results are\n"
                            "synthetic and labelled [DEMO] everywhere.",
                 font=theme.ui(9), bg=theme.SURFACE, fg=theme.MUTED, justify="left").pack(side="left")
        self.demo_toggle = Toggle(drow, command=self.set_demo_mode)
        self.demo_toggle.pack(side="right", padx=S(6))

        health = Card(page, "Provider Health")
        health.pack(fill="both", expand=True)
        FlatButton(health.header, "▶ RUN CHECK", self.run_diagnostics, bg=theme.SURFACE_2, fg=theme.GREEN,
                   font=theme.mono(8, "bold"), padx=10, pady=3).pack(side="right")
        self.health_rows = {}
        grid = tk.Frame(health.body, bg=theme.SURFACE)
        grid.pack(fill="x", pady=(S(6), 0))
        for c, (text, w) in enumerate((("PROVIDER", 26), ("HOST", 30), ("MODULES", 22), ("STATUS", 12), ("LATENCY", 10))):
            tk.Label(grid, text=text, font=theme.mono(8, "bold"), bg=theme.SURFACE, fg=theme.DIM, width=w,
                     anchor="w").grid(row=0, column=c, sticky="w", pady=(0, S(6)))
        for r, prov in enumerate(self.engine.providers, start=1):
            mods = ", ".join(t.label for t in prov.target_types)
            values = (prov.name, prov.host, mods)
            for c, v in enumerate(values):
                tk.Label(grid, text=v, font=theme.mono(9), bg=theme.SURFACE,
                         fg=theme.TEXT if c == 0 else theme.MUTED, anchor="w").grid(row=r, column=c, sticky="w", pady=S(4))
            status = tk.Label(grid, text="○ untested", font=theme.mono(9, "bold"), bg=theme.SURFACE, fg=theme.DIM, anchor="w")
            status.grid(row=r, column=3, sticky="w")
            latency = tk.Label(grid, text="—", font=theme.mono(9), bg=theme.SURFACE, fg=theme.MUTED, anchor="w")
            latency.grid(row=r, column=4, sticky="w")
            self.health_rows[prov.host] = (status, latency)
        return page

    # ----------------------------------------------------------- about page
    def _build_about_page(self):
        page = tk.Frame(self.content, bg=theme.BG)
        self._page_title(page, "ⓘ", f"About {APP_NAME}",
                         f"v{__version__} · A personal breach & exposure intelligence console · Python + Tkinter")

        card = Card(page, "How the password check stays private (k-anonymity)")
        card.pack(fill="x", pady=(0, S(12)))
        c = tk.Canvas(card.body, height=S(150), bg=theme.SURFACE, highlightthickness=0)
        c.pack(fill="x", pady=S(6))
        c.bind("<Configure>", lambda e: self._draw_kanon(c))

        lower = tk.Frame(page, bg=theme.BG)
        lower.pack(fill="both", expand=True)
        lower.grid_columnconfigure(0, weight=1, uniform="a")
        lower.grid_columnconfigure(1, weight=1, uniform="a")
        lower.grid_rowconfigure(0, weight=1)
        arch = Card(lower, "Architecture")
        arch.grid(row=0, column=0, sticky="nsew", padx=(0, S(12)))
        info = Card(lower, "Data Sources & Shortcuts")
        info.grid(row=0, column=1, sticky="nsew")

        def bullets(parent, rows):
            for head, text in rows:
                line = tk.Frame(parent, bg=theme.SURFACE)
                line.pack(fill="x", pady=S(3))
                tk.Label(line, text="▸ " + head, font=theme.mono(9, "bold"), bg=theme.SURFACE, fg=theme.GREEN,
                         width=22, anchor="nw").pack(side="left", anchor="n")
                tk.Label(line, text=text, font=theme.ui(9), bg=theme.SURFACE, fg=theme.MUTED, justify="left",
                         anchor="w", wraplength=S(330)).pack(side="left", fill="x")

        bullets(arch.body, (
            ("Strategy pattern", "Each API is a BreachProvider subclass; the engine picks one at runtime."),
            ("Template method", "BreachProvider.scan() handles timeouts & network errors once for all providers."),
            ("Polymorphic targets", "ScanTarget subclasses validate and normalise their own input."),
            ("Threaded scans", "Lookups run on a worker thread and report back through a queue, so the UI never freezes."),
            ("Zero dependencies", "Pure standard library - even Keccak-512 is implemented from scratch."),
        ))
        bullets(info.body, (
            ("XposedOrNot", "Email breaches & password k-anonymity checks"),
            ("LeakCheck", "Username & phone breach sources"),
            ("AbuseIPDB", "IP abuse reputation (free API key)"),
            ("AlienVault OTX", "Domain threat-intelligence pulses"),
            ("Ctrl+1…6 / Enter", "Switch module / run scan · Ctrl+H history · Ctrl+D diagnostics · Esc clear"),
        ))
        return page

    def _draw_kanon(self, c: tk.Canvas):
        c.delete("all")
        w = c.winfo_width()
        boxes = (("your password", "hunter2", theme.TEXT), ("Keccak-512 (local)", "a3f9c1e07b5d…128 hex", theme.ACCENT),
                 ("prefix only", "a3f9c1e07b", theme.GREEN), ("XposedOrNot API", "returns breach count", theme.WARN))
        n, gap = len(boxes), S(40)
        bw = (w - gap * (n - 1) - S(20)) / n
        y0, y1 = S(30), S(92)
        for i, (title, sub, color) in enumerate(boxes):
            x0 = S(10) + i * (bw + gap)
            c.create_rectangle(x0, y0, x0 + bw, y1, outline=blend(color, theme.SURFACE, 0.3), width=S(1),
                               fill=blend(color, theme.SURFACE, 0.92))
            c.create_text(x0 + bw / 2, y0 + S(20), text=title.upper(), font=theme.mono(8, "bold"), fill=color)
            c.create_text(x0 + bw / 2, y0 + S(42), text=sub, font=theme.mono(9), fill=theme.MUTED)
            if i < n - 1:
                ax = x0 + bw + S(6)
                c.create_line(ax, (y0 + y1) / 2, ax + gap - S(12), (y0 + y1) / 2, fill=theme.MUTED,
                              arrow="last", width=S(2))
        boundary = S(10) + 3 * (bw + gap) - gap / 2
        c.create_line(boundary, S(6), boundary, S(116), fill=theme.DANGER, dash=(4, 3), width=S(1))
        c.create_text(boundary - S(8), S(12), text="YOUR COMPUTER", anchor="e", font=theme.mono(7, "bold"), fill=theme.MUTED)
        c.create_text(boundary + S(8), S(12), text="INTERNET", anchor="w", font=theme.mono(7, "bold"), fill=theme.MUTED)
        c.create_text(w / 2, S(130), font=theme.ui(9), fill=theme.MUTED,
                      text="Only 10 of 128 hash characters cross the line. The full password and full hash never leave your machine.")

    def _page_title(self, page, icon, title, subtitle):
        head = tk.Frame(page, bg=theme.BG)
        head.pack(fill="x", pady=(0, S(14)))
        tk.Label(head, text=icon, font=theme.symbol(24), bg=theme.BG, fg=theme.ACCENT, width=2).pack(
            side="left", padx=(0, S(10)))
        t = tk.Frame(head, bg=theme.BG)
        t.pack(side="left", fill="x")
        tk.Label(t, text=title, font=theme.ui(18, "bold"), bg=theme.BG, fg=theme.TEXT, anchor="w").pack(fill="x")
        tk.Label(t, text=subtitle, font=theme.ui(10), bg=theme.BG, fg=theme.MUTED, anchor="w").pack(fill="x")

    def _bind_keys(self):
        for i, mod in enumerate(MODULES, start=1):
            self.bind(f"<Control-Key-{i}>", lambda e, m=mod: self.show_module(m))
        self.bind("<Control-h>", lambda e: self.show_page("history"))
        self.bind("<Control-d>", lambda e: self.show_page("diagnostics"))
        self.bind("<Escape>", lambda e: self._clear_input())

    # ============================================================ navigation
    def _select_nav(self, key):
        for k, item in self.nav.items():
            item.set_selected(k == key)

    def show_page(self, key: str):
        self.pages[key].tkraise()
        self._select_nav(key if key != "scan" else self.module.kind)
        if key == "history":
            self._refresh_history()

    def show_module(self, mod: Module):
        if self.scanning:
            self.pages["scan"].tkraise()
            self._select_nav(self.module.kind)
            self.set_status("Scan in progress - wait for it to finish before switching modules.")
            return
        changed = mod is not self.module
        self.module = mod
        self.mod_icon.configure(text=mod.icon)
        self.mod_title.configure(text=mod.title)
        self.mod_desc.configure(text=mod.description)
        self.mod_source.configure(text=("DEMO DATASET" if self.engine.demo_mode else mod.source.upper()))
        if changed or self.entry.value() == "":
            self.entry.clear()
        self.entry.set_placeholder(mod.placeholder)
        is_password = mod.kind == "password"
        self.entry.set_secret(is_password)
        if is_password:
            self.eye.configure(text="SHOW")
            self.eye.pack(side="left", padx=(S(6), 0))
            self.strength_box.pack(side="right")
        else:
            self.eye.pack_forget()
            self.strength_box.pack_forget()
        self._update_strength()
        self._set_hint("Press Enter or ▶ SCAN to run the lookup.")
        self.pages["scan"].tkraise()
        self._select_nav(mod.kind)
        self.visual.set_idle(f"{mod.title.lower()} · ready")
        self._show_intro(mod)
        self.entry.focus_set()

    def _show_intro(self, mod: Module):
        self._cancel_reveal()
        self.current_result = None
        f = self.findings
        f.configure(state="normal")
        f.delete("1.0", "end")
        f.insert("end", f"{mod.icon}  {mod.title.upper()}\n", ("heading",))
        f.insert("end", "─" * 52 + "\n", ("dim",))
        for line in mod.intro:
            f.insert("end", line + "\n", ("muted",))
        if self.engine.demo_mode:
            f.insert("end", "\n⚠ DEMO MODE is on - results come from a synthetic offline dataset.\n", ("warn",))
        f.insert("end", "\nAwaiting target_", ("accent",))
        f.configure(state="disabled")

    # ================================================================ scanning
    def start_scan(self):
        if self.scanning:
            return
        try:
            target = make_target(self.module.kind, self.entry.value())
        except ValueError as err:
            self._set_hint(f"✖ {err}", error=True)
            self.log("err", f"Input rejected: {err}")
            self._flash_entry()
            return

        self.scanning = True
        self.scan_btn.set_enabled(False, "◌  SCANNING")
        provider = self.engine.provider_for(target)
        self.visual.set_scanning(f"{provider.host or 'offline dataset'} · {target.display}")
        self._set_hint(f"Querying {provider.name}...")
        self.set_status(f"Scanning {target.label.lower()} via {provider.name}...")
        self._show_scanning(target)
        self.log("sys", f"Scan started · module={target.kind} · target={target.display}")
        if target.kind == "password":
            self.entry.clear()  # don't leave the secret sitting in the widget
            self._update_strength()
        threading.Thread(target=self._scan_worker, args=(target,), daemon=True).start()

    def _scan_worker(self, target):
        started = time.perf_counter()
        result = self.engine.scan(target, lambda level, msg: self.events.put(("log", level, msg)))
        remaining = MIN_SCAN_SECONDS - (time.perf_counter() - started)
        if remaining > 0:
            time.sleep(remaining)
        self.events.put(("result", result))

    def _poll_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "log":
                    self.log(event[1], event[2])
                elif event[0] == "result":
                    self._finish_scan(event[1])
                elif event[0] == "health":
                    self._show_health(*event[1:])
        except queue.Empty:
            pass
        self.after(40, self._poll_events)

    def _finish_scan(self, result: ScanResult):
        self.scanning = False
        self.scan_btn.set_enabled(True, "▶  SCAN")
        self.history.append(result)
        self.visual.set_result(result)
        self.render_result(result)
        self._update_stats()
        level = result.risk
        tag = {"SAFE": "info", "CAUTION": "warn", "EXPOSED": "warn", "CRITICAL": "err", "ERROR": "err"}[level.name]
        self.log(tag, f"Verdict: {level.label} · score {result.score}/100 · {result.elapsed:.2f}s")
        self.set_status(f"Last scan: {level.label} - {result.status}")
        self._set_hint("Scan complete. Enter another target or switch module.")
        if level in (RiskLevel.CRITICAL, RiskLevel.EXPOSED):
            self.bus.alert(level.color)
            self._alert_logo(level.color)

    def _show_scanning(self, target):
        self._cancel_reveal()
        f = self.findings
        f.configure(state="normal")
        f.delete("1.0", "end")
        f.insert("end", "INTERCEPTING...\n", ("heading",))
        f.insert("end", "─" * 52 + "\n", ("dim",))
        f.insert("end", f"target    {target.display}\n", ("muted",))
        f.insert("end", f"module    {target.label}\n", ("muted",))
        f.configure(state="disabled")
        self._scramble_tick(0)

    def _scramble_tick(self, n):
        if not self.scanning:
            return
        f = self.findings
        f.configure(state="normal")
        f.delete("5.0", "end")
        for _ in range(6):
            f.insert("end", "\n" + "".join(random.choice(SCRAMBLE) for _ in range(random.randint(18, 48))), ("scramble",))
        f.configure(state="disabled")
        self._reveal_job = self.after(70, self._scramble_tick, n + 1)

    def render_result(self, result: ScanResult, animate: bool = True):
        self._cancel_reveal()
        self.current_result = result
        f = self.findings
        f.configure(state="normal")
        f.delete("1.0", "end")
        f.insert("end", f"■ {result.risk.label}\n", (result.risk.name, "title"))
        when = time.strftime("%H:%M:%S", time.localtime(result.timestamp))
        f.insert("end", f"{result.status}\n", ("muted",))
        f.insert("end", f"{result.source} · {result.target} · {result.elapsed:.2f}s · {when}\n", ("dim",))
        f.insert("end", "─" * 52 + "\n", ("dim",))
        f.configure(state="disabled")
        lines = list(result.details)
        if animate:
            self._reveal_lines(lines, 0)
        else:
            for line in lines:
                self._insert_detail(line)

    def _reveal_lines(self, lines, i):
        """Each line shows as scrambled glyphs for a moment, then 'decrypts'."""
        if i >= len(lines):
            self._reveal_job = None
            return
        f = self.findings
        f.configure(state="normal")
        line = lines[i]
        f.insert("end", "".join(random.choice(SCRAMBLE) if ch != " " else " " for ch in line[:60]) + "\n", ("scramble",))
        f.configure(state="disabled")

        def settle():
            f.configure(state="normal")
            f.delete("end-2l linestart", "end-1c")
            f.configure(state="disabled")
            self._insert_detail(line)
            self._reveal_job = self.after(22, self._reveal_lines, lines, i + 1)

        self._reveal_job = self.after(45, settle)

    def _insert_detail(self, line: str):
        f = self.findings
        f.configure(state="normal")
        if line.startswith("⚠"):
            f.insert("end", line + "\n", ("warn",))
        elif line.startswith(("ℹ", "✔")):
            f.insert("end", line + "\n", ("accent",))
        elif line.startswith("•"):
            f.insert("end", "   " + line + "\n", ("muted",))
        elif line.endswith(":"):
            f.insert("end", line + "\n", ("heading",))
        elif ": " in line and not line.startswith("["):
            key, _, val = line.partition(": ")
            f.insert("end", "▸ ", ("ok",))
            f.insert("end", key + ": ", ("muted",))
            f.insert("end", val + "\n")
        else:
            f.insert("end", "▸ ", ("ok",))
            f.insert("end", line + "\n")
        f.configure(state="disabled")

    def _cancel_reveal(self):
        if self._reveal_job is not None:
            self.after_cancel(self._reveal_job)
            self._reveal_job = None

    # ================================================================ helpers
    def log(self, level: str, message: str):
        t = self.log_text
        t.configure(state="normal")
        t.insert("end", time.strftime("[%H:%M:%S] "), ("time",))
        t.insert("end", message + "\n", (level,))
        if int(t.index("end-1c").split(".")[0]) > 500:
            t.delete("1.0", "100.0")
        t.see("end")
        t.configure(state="disabled")

    def set_status(self, text: str):
        self.status_left.configure(text="● " + text)

    def _set_hint(self, text, error=False):
        self.hint.configure(text=text, fg=theme.DANGER if error else theme.MUTED)

    def _flash_entry(self, n=0):
        self.entry.configure(highlightbackground=theme.DANGER if n % 2 == 0 else theme.BORDER,
                             highlightcolor=theme.DANGER if n % 2 == 0 else theme.ACCENT)
        if n < 5:
            self.after(110, self._flash_entry, n + 1)

    def _toggle_reveal(self):
        self.entry.toggle_reveal()
        self.eye.configure(text="HIDE" if self.entry.reveal else "SHOW")

    def _clear_input(self):
        self.entry.clear()
        self.entry.focus_set()
        self._update_strength()

    def _update_strength(self):
        if self.module.kind != "password":
            return
        pw = self.entry.value()
        if not pw:
            self.strength.set(-1)
            self.strength_label.configure(text="strength: —", fg=theme.MUTED)
            return
        report = strength.analyze(pw)
        self.strength.set(report.score)
        self.strength_label.configure(text=f"{report.label.lower()} · cracked in {report.crack_time}",
                                      fg=StrengthMeter.COLORS[report.score])

    def _update_stats(self):
        threats = sum(1 for r in self.history if r.risk.is_threat)
        self.side_stats.configure(text=f"scans     {len(self.history)}\nthreats   {threats}\n"
                                       f"mode      {'DEMO' if self.engine.demo_mode else 'LIVE'}")

    def _update_mode_pill(self):
        if self.engine.demo_mode:
            self.mode_pill.configure(text="● DEMO MODE", bg=blend(theme.WARN, theme.SURFACE, 0.8), fg=theme.WARN)
        else:
            self.mode_pill.configure(text="● LIVE", bg=blend(theme.GREEN, theme.SURFACE, 0.85), fg=theme.GREEN)

    def _tick_clock(self):
        self.clock.configure(text=time.strftime("%H:%M:%S"))
        up = int(time.time() - self.started)
        self.status_right.configure(text=f"uptime {up // 3600:02d}:{up % 3600 // 60:02d}:{up % 60:02d}  ·  "
                                         f"{APP_NAME} v{__version__}")
        self.after(1000, self._tick_clock)

    def _glitch_logo(self):
        """Every few seconds the logo briefly corrupts, then restores."""
        original = "◢◤ SHADOWSCAN"

        def corrupt(step):
            if step < 4:
                chars = list(original)
                for _ in range(3):
                    i = random.randrange(3, len(chars))
                    chars[i] = random.choice("█▓▒░#@$%")
                self.logo.configure(text="".join(chars), fg=random.choice((theme.ACCENT, theme.DANGER, theme.GREEN)))
                self.after(60, corrupt, step + 1)
            else:
                self.logo.configure(text=original, fg=theme.ACCENT)

        corrupt(0)
        self.after(random.randint(5000, 9000), self._glitch_logo)

    def _alert_logo(self, color, n=0):
        if n < 6:
            self.logo.configure(fg=color if n % 2 == 0 else theme.ACCENT)
            self.after(160, self._alert_logo, color, n + 1)

    def copy_findings(self):
        text = self.findings.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(text)
        self.set_status("Findings copied to clipboard.")

    # ============================================================== history
    def _refresh_history(self):
        self.tree.delete(*self.tree.get_children())
        titles = {m.kind: m.title for m in MODULES}
        for idx, r in reversed(list(enumerate(self.history))):
            self.tree.insert("", "end", iid=str(idx), tags=(r.risk.name,), values=(
                time.strftime("%H:%M:%S", time.localtime(r.timestamp)), titles.get(r.module, r.module),
                r.target, r.risk.label, "--" if r.risk is RiskLevel.ERROR else r.score, r.source, f"{r.elapsed:.2f}s"))
        counts = {lvl.name: 0 for lvl in RiskLevel}
        for r in self.history:
            counts[r.risk.name] += 1
        self.tiles["total"].configure(text=str(len(self.history)))
        for key in ("CRITICAL", "EXPOSED", "CAUTION", "SAFE"):
            self.tiles[key].configure(text=str(counts[key]))
        if self.history:
            self.empty_history.place_forget()
        else:
            self.empty_history.place(relx=0.5, rely=0.45, anchor="center")

    def open_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        result = self.history[int(sel[0])]
        mod = next(m for m in MODULES if m.kind == result.module)
        self.show_module(mod)
        self.visual.set_result(result)
        self.render_result(result, animate=False)

    def clear_history(self):
        if self.history and messagebox.askyesno(APP_NAME, "Clear all scan history for this session?", parent=self):
            self.history.clear()
            self._refresh_history()
            self._update_stats()

    def export_report(self, fmt: str, results: list[ScanResult]):
        if not results:
            messagebox.showinfo(APP_NAME, "Nothing to export yet - run a scan first.", parent=self)
            return
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=f".{fmt}", initialfile=f"shadowscan-report-{stamp}.{fmt}",
            filetypes=[("JSON", "*.json")] if fmt == "json" else [("Text report", "*.txt")])
        if not path:
            return
        if fmt == "json":
            content = json.dumps({"generated": time.strftime("%Y-%m-%d %H:%M:%S"), "tool": f"{APP_NAME} v{__version__}",
                                  "results": [r.to_dict() for r in results]}, indent=2, ensure_ascii=False)
        else:
            content = self._text_report(results)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        self.log("sys", f"Report exported -> {path}")
        self.set_status(f"Report saved: {path}")

    def _text_report(self, results):
        titles = {m.kind: m.title for m in MODULES}
        out = ["=" * 72, f"  {APP_NAME.upper()} EXPOSURE REPORT", f"  generated {time.strftime('%Y-%m-%d %H:%M:%S')}"
               f"  ·  {len(results)} scan(s)", "=" * 72, ""]
        for r in results:
            d = r.to_dict()
            out += [f"[{d['verdict']}] {titles.get(r.module, r.module)}  -  {r.target}",
                    f"  score {d['score']}/100 · {r.status} · source: {r.source} · {d['timestamp']}"]
            out += [f"    {line}" for line in r.details]
            out.append("-" * 72)
        out.append("Generated by ShadowScan - for personal, educational use only.")
        return "\n".join(out) + "\n"

    # ========================================================== diagnostics
    def _abuse_key(self) -> str:
        return os.environ.get(ABUSE_KEY, "").strip()

    def _update_key_status(self):
        if self._abuse_key():
            k = self._abuse_key()
            self.key_status.configure(text=f"✔ configured ({k[:4]}…{k[-4:]})", fg=theme.GREEN)
        else:
            self.key_status.configure(text="✖ not configured", fg=theme.DANGER)

    def save_key(self):
        key = self.key_entry.value().strip()
        config.save_env_value(ABUSE_KEY, key)
        self.key_entry.clear()
        self._update_key_status()
        self.log("sys", "AbuseIPDB key saved to .env" if key else "AbuseIPDB key removed")

    def set_demo_mode(self, on: bool):
        self.engine.demo_mode = on
        self._update_mode_pill()
        self._update_stats()
        self.mod_source.configure(text="DEMO DATASET" if on else self.module.source.upper())
        self.log("warn" if on else "sys", "Demo mode ENABLED - offline sample data" if on else "Demo mode disabled - live APIs")
        self._show_intro(self.module)

    def run_diagnostics(self):
        for status, latency in self.health_rows.values():
            status.configure(text="◌ testing", fg=theme.ACCENT)
            latency.configure(text="…")
        self.log("sys", "Running provider health check...")

        def work():
            for prov in self.engine.providers:
                self.events.put(("health", prov.host, ping(prov.host)))
        threading.Thread(target=work, daemon=True).start()

    def _show_health(self, host, latency_ms):
        status, latency = self.health_rows[host]
        if latency_ms is None:
            status.configure(text="● offline", fg=theme.DANGER)
            latency.configure(text="—")
            self.log("err", f"{host} unreachable")
        else:
            color = theme.GREEN if latency_ms < 800 else theme.WARN
            status.configure(text="● online", fg=color)
            latency.configure(text=f"{latency_ms:.0f} ms")
            self.log("info", f"{host} online · {latency_ms:.0f} ms")


def main():
    app = ShadowScanApp(splash="--no-splash" not in sys.argv)
    app.mainloop()
