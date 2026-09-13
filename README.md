# ShadowScan — Terminal Breach Intelligence Tool

A personal breach/exposure intelligence CLI tool with a hacker-terminal aesthetic, built in Java with clean OOP design principles.

![Java](https://img.shields.io/badge/Java-11%2B-orange) ![License](https://img.shields.io/badge/License-Educational-blue)

---

## Features

ShadowScan provides 5 lookup modules, each backed by a real free API:

| Module | API | Auth Required |
|--------|-----|---------------|
| **Email Breach Check** | XposedOrNot | No |
| **Password Exposure Check** | XposedOrNot (k-anonymity) | No |
| **Username Exposure Check** | LeakCheck Public API | No |
| **Phone Number Exposure Check** | LeakCheck Public API | No |
| **IP Reputation Check** | AbuseIPDB | Yes (free key) |
| **Domain Threat Intelligence** | AlienVault OTX | No |

### Terminal Aesthetic
- Matrix rain intro animation
- Typewriter boot sequence with ASCII banner
- "Hacker-speed" typewriter input prompts
- Matrix encryption/decryption processing sequences
- Randomized scanning spinners (braille, radar sweep, glitch progress)
- Letter-by-letter result reveals with glitch effects on critical findings
- Cinematic shutdown disconnect sequences
- Animated menu transitions
- Persistent status header bar

**No run looks identical to the last one** — animations are randomly selected from a pool.

---

## Quick Start

### Prerequisites
- **Java 11+** (tested with Java 25)
- Internet connection for API calls

### Build & Run

Since Gradle currently lacks full support for Java 25, convenient PowerShell scripts are provided for direct compilation.

```powershell
cd ShadowScan

# Download dependencies and compile
.\build.ps1

# Run the application
.\run.ps1
```

*(If you are on an older Java version like Java 21, you can also use `./gradlew run`)*

### Testing & CI/CD
ShadowScan uses JUnit 5 for rigorous validation.
You can run the entire test suite locally using the included script:
```powershell
.\test.ps1
```
*(ShadowScan also includes a GitHub Actions workflow for automatic CI/CD validation on every push!)*

### API Key Setup (for IP Reputation module)

1. Sign up for a free API key at [AbuseIPDB](https://www.abuseipdb.com/account/api)
2. Set the environment variable:
   ```bash
   # Linux/Mac
   export ABUSEIPDB_KEY=your_api_key_here

   # Windows (CMD)
   set ABUSEIPDB_KEY=your_api_key_here

   # Windows (PowerShell)
   $env:ABUSEIPDB_KEY = "your_api_key_here"
   ```
3. Run ShadowScan — the IP Reputation module will now work

> The other 4 modules work without any API key.

---

## OOP Design Decisions

### Strategy Pattern (BreachProvider)

The core architectural pattern is **Strategy**. Each API integration implements the `BreachProvider` interface:

```
BreachProvider (interface)
├── XposedOrNotProvider        → Email breach checking
├── XposedOrNotPasswordProvider → Password k-anonymity checking
├── LeakCheckProvider          → Username + Phone lookups
├── AbuseIpdbProvider          → IP reputation checking
└── AlienVaultDomainProvider   → Domain OSINT & Pulses
```

**Why Strategy?** New data sources can be added by implementing `BreachProvider` and registering with the `ScanEngine` — zero changes to existing code. The engine selects the right provider at runtime via `supports(ScanTarget)`.

### Interface Boundaries

```
ScanTarget (interface)          → What to scan (email, password, etc.)
BreachProvider (interface)      → How to scan (which API, what parsing)
ScanResult (model)              → Normalized result regardless of source
RiskScorer (utility)            → Raw data → Safe/Caution/Exposed/Critical
TerminalRenderer                → ALL visual output (fully separated from logic)
ScanAnimation (interface)       → Pluggable animation implementations
```

**Key boundary**: `TerminalRenderer` owns every `System.out.print` call. The logic layer (providers, engine, scorer) never prints directly. This means the entire API integration layer is testable without a terminal.

### k-Anonymity (Password Module)

The password module implements the **k-anonymity model**:
1. Password is hashed locally with SHA3 Keccak-512 (via Bouncy Castle)
2. Only the first 10 hex characters of the hash are sent to the API
3. The full password and full hash **never leave the client**
4. This is enforced at the code level — the full hash exists only as a local variable in `computeKeccak512Prefix()` and is never stored, returned, or transmitted

---

## Package Structure

```
shadowscan/
├── ShadowScan.java                    # Main entry point
├── core/
│   ├── ScanTarget.java                # Interface — polymorphic scan target
│   ├── EmailTarget.java               # Email with format validation
│   ├── PasswordTarget.java            # Password (hashed locally, never sent)
│   ├── UsernameTarget.java            # Username
│   ├── PhoneTarget.java               # Phone number with normalization
│   ├── IpTarget.java                  # IP with v4/v6 validation
│   ├── BreachProvider.java            # Strategy pattern interface
│   ├── RiskScorer.java                # Risk classification logic
│   └── ScanEngine.java                # Orchestrator
├── model/
│   ├── ScanResult.java                # Normalized result (Builder pattern)
│   └── RiskLevel.java                 # Enum: SAFE/CAUTION/EXPOSED/CRITICAL
├── providers/
│   ├── XposedOrNotProvider.java       # Email breach + analytics
│   ├── XposedOrNotPasswordProvider.java # Keccak-512 + k-anonymity
│   ├── LeakCheckProvider.java         # Username + Phone
│   ├── AbuseIpdbProvider.java         # IP reputation
│   └── AlienVaultDomainProvider.java  # Domain threat intelligence
└── ui/
    ├── AnsiPainter.java               # ANSI escape code helper
    ├── TerminalRenderer.java          # All visual output
    ├── ScanAnimation.java             # Animation interface
    ├── AnimationPool.java             # Random picker (no repeats)
    └── animations/
        ├── MatrixRainAnimation.java
        ├── TypewriterBootAnimation.java
        ├── BrailleSpinnerAnimation.java
        ├── RadarSpinnerAnimation.java
        ├── GlitchProgressAnimation.java
        ├── ResultRevealAnimation.java
        ├── DataStreamAnimation.java
        ├── MenuWipeAnimation.java
        ├── MatrixProcessingAnimation.java
        └── ShutdownAnimation.java
```

---

## Dependencies

| Dependency | Purpose | Maven Coordinates |
|------------|---------|-------------------|
| **Bouncy Castle** | Keccak-512 hashing for password k-anonymity | `org.bouncycastle:bcprov-jdk18on:1.78.1` |
| **Gson** | JSON parsing for API responses | `com.google.code.gson:gson:2.11.0` |
| **java.net.http** | HTTP client (built-in, Java 11+) | — |

---

## API Rate Limits

| API | Rate Limit | Daily Limit |
|-----|------------|-------------|
| XposedOrNot (email) | 2/sec | 100/day |
| XposedOrNot (password) | No published limit | — |
| LeakCheck (public) | 1/sec | — |
| AbuseIPDB (free tier) | — | 1000/day |

---

## License

Educational project — built for an Advanced Programming Practice course. APIs used under their respective free-tier terms.
