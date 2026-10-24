# ShadowScan — Breach Intelligence Console

A desktop app that checks whether your email, passwords, usernames, phone numbers, IPs or domains have shown up in known data breaches and threat-intelligence feeds. Built with **Python + Tkinter** and a dark "cyber console" look.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![GUI](https://img.shields.io/badge/GUI-Tkinter-green) ![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

---

## Features

| Module | What it checks | Data source | API key |
|---|---|---|---|
| ✉ **Email Breach Check** | Breaches containing the email, exposed data types, breach timeline | XposedOrNot | No |
| ✱ **Password Exposure** | How many times a password appears in leaked dumps (k-anonymity) | XposedOrNot | No |
| ☺ **Username Exposure** | Breach sources containing the username | LeakCheck | No |
| ☎ **Phone Exposure** | Breach sources containing the phone number | LeakCheck | No |
| ⌖ **IP Reputation** | Abuse reports (spam, brute-force, scanning), ISP, Tor exit | AbuseIPDB | Yes (free) |
| ◎ **Domain Threat Intel** | Threat pulses, linked malware families / threat actors | AlienVault OTX | No |

### Interface highlights
- **Boot sequence**: matrix "digital rain" with a typewriter terminal intro (press any key to skip)
- **Threat radar**: an animated sweep with blips and pings while a scan runs
- **Threat gauge**: the radar turns into a 0–100 threat-score gauge colour-coded by verdict
- **Decrypting findings**: result lines appear as scrambled glyphs, then "decrypt" into text
- **Live password strength meter**: entropy and estimated crack time, calculated offline as you type
- **Activity log**: a timestamped console showing each request the app makes
- **Scan history**: verdict summary tiles, a results table, and export to **.txt** or **.json**
- **Diagnostics**: AbuseIPDB key setup, live provider health check with latency, and an **offline demo mode**
- **About page**: a diagram of how the k-anonymity password check works

### Verdicts
`SAFE` → `CAUTION` → `EXPOSED` → `CRITICAL` (plus `ERROR` when a lookup fails). Each module has its own thresholds, because a "breach count" and an "abuse confidence %" mean different things.

---

## Quick start

Requirements: **Python 3.10+**, which includes Tkinter on Windows and macOS. There are no packages to install.

```bash
python main.py              # with boot animation
python main.py --no-splash  # skip straight to the console
# or
python -m shadowscan
```

> On Linux you may need the Tk package: `sudo apt install python3-tk`

### Optional: AbuseIPDB key (IP Reputation only)
1. Get a free key at <https://www.abuseipdb.com/account/api>.
2. In the app, open **Diagnostics**, paste the key and click **Save**. It is stored in a local `.env` file, which git ignores.

   You can also copy `.env.example` to `.env` and fill in the key, or set the `ABUSEIPDB_KEY` environment variable.

### Presenting without internet?
Turn on **Diagnostics → Offline Demo Mode**. Every module then returns results from a built-in sample dataset. These results are deterministic and clearly labelled `[DEMO]`.

### Keyboard shortcuts
| Keys | Action |
|---|---|
| `Ctrl+1` … `Ctrl+6` | Switch scan module |
| `Enter` | Run scan |
| `Esc` | Clear input |
| `Ctrl+H` / `Ctrl+D` | History / Diagnostics |

---

## How the password check stays private

```
"hunter2" ──► Keccak-512 (on your PC) ──► first 10 hex chars ──►  API
                128 hex characters          e.g. "a3f9c1e07b"     returns counts
└──────────── never leaves your computer ────────────┘
```

Thousands of different passwords share the same 10-character prefix, so the server cannot tell which password you typed. This is called **k-anonymity**. The password field is also cleared as soon as a scan starts.

Keccak-512 (the original Keccak, *not* `hashlib.sha3_512`, which uses different padding) is implemented from scratch in [`shadowscan/keccak.py`](shadowscan/keccak.py). It is checked against `hashlib`'s SHA-3, which uses the same permutation, in the unit tests.

---

## Project structure

```
ShadowScan/
├── main.py                     # entry point
├── shadowscan/
│   ├── models.py               # RiskLevel enum, ScanResult dataclass
│   ├── targets.py              # ScanTarget + 6 validating subclasses, make_target() factory
│   ├── scoring.py              # per-module risk thresholds
│   ├── engine.py               # ScanEngine - routes a target to the right provider
│   ├── keccak.py               # pure-Python Keccak-512
│   ├── strength.py             # offline password entropy / crack-time estimator
│   ├── net.py                  # tiny urllib JSON client + ping
│   ├── config.py               # .env loading / saving
│   ├── providers/
│   │   ├── base.py             # BreachProvider abstract base (template method)
│   │   ├── xposedornot.py      # email + password
│   │   ├── leakcheck.py        # username + phone
│   │   ├── abuseipdb.py        # IP reputation
│   │   ├── alienvault.py       # domain threat intel
│   │   └── demo.py             # offline demo dataset
│   └── gui/
│       ├── app.py              # main window, pages, scan workflow
│       ├── widgets.py          # radar/gauge, matrix rain, buttons, toggle, meters
│       ├── splash.py           # boot animation
│       └── theme.py            # colours, fonts, DPI scaling
└── tests/test_core.py          # 29 unit tests (no network needed)
```

### Design decisions
- **Strategy pattern**: every API is a `BreachProvider` subclass. `ScanEngine` picks the provider that `supports()` the target, so adding a new data source does not touch any UI code.
- **Template method**: `BreachProvider.scan()` handles timeouts, network errors and unexpected failures in one place. Subclasses implement only `_scan()`, which parses their own API's response.
- **Polymorphic targets**: each `ScanTarget` subclass validates and normalises its own input. For example, `DomainTarget` accepts a pasted URL and `PhoneTarget` strips formatting. `PasswordTarget` masks itself in `display` and `repr`.
- **Responsive UI**: scans run on a worker thread and send log lines and results back through a `queue.Queue`, which the Tk main loop polls. The window never freezes.
- **Core is separate from GUI**: everything outside `gui/` works without Tkinter and is fully unit-tested with mocked HTTP.

---

## Running the tests

```bash
python -m unittest discover tests -v
```

GitHub Actions runs the suite on Windows and Ubuntu with Python 3.10, 3.12 and 3.13 on every push.

---

## Disclaimer
For **educational and personal use only**. Check only accounts, IPs and domains that you own or are authorised to assess. ShadowScan shows breach *metadata* only (source names, dates, data categories). It never retrieves leaked data itself.
