package shadowscan.ui;

import shadowscan.model.RiskLevel;
import shadowscan.model.ScanResult;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * Owns ALL visual output for the ShadowScan CLI.
 * Logic classes (providers, engine) never print directly — this ensures
 * the API/OOP work stays clean and testable independent of the UI layer.
 */
public class TerminalRenderer {

    private static final int TERM_WIDTH = 80;
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private String currentModule = "Main Menu";

    public void setCurrentModule(String module) {
        this.currentModule = module;
    }

    // ─── Header Bar ────────────────────────────────────────────────────

    /**
     * Persistent header bar at the top of every screen.
     */
    public void renderHeader() {
        String timestamp = LocalDateTime.now().format(TIME_FMT);
        String header = " SHADOWSCAN v1.0 │ " + currentModule + " │ " + timestamp + " ";
        int padding = Math.max(0, TERM_WIDTH - header.length());

        System.out.println(AnsiPainter.BOLD + AnsiPainter.BG_DARK + AnsiPainter.NEON_GREEN
                + header + AnsiPainter.repeat(' ', padding) + AnsiPainter.RESET);
        System.out.println(AnsiPainter.colorize(AnsiPainter.repeat('═', TERM_WIDTH), AnsiPainter.DIM_GRAY));
    }

    // ─── Main Menu ─────────────────────────────────────────────────────

    public void renderMainMenu() {
        setCurrentModule("Main Menu");
        AnsiPainter.clearScreen();
        renderHeader();
        System.out.println();

        String[] miniLogo = {
            "   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗   ███████╗ ██████╗ █████╗ ███╗   ██╗",
            "   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║   ██╔════╝██╔════╝██╔══██╗████╗  ██║",
            "   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║   ███████╗██║     ███████║██╔██╗ ██║",
            "   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║   ╚════██║██║     ██╔══██║██║╚██╗██║",
            "   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝   ███████║╚██████╗██║  ██║██║ ╚████║",
            "   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
        };

        for (String line : miniLogo) {
            System.out.println(AnsiPainter.colorize(line, AnsiPainter.NEON_GREEN));
        }

        System.out.println();
        System.out.println(AnsiPainter.colorize("  ─── SELECT SCAN MODULE ───", AnsiPainter.CYAN));
        System.out.println();

        renderMenuItem("1", "Email Breach Check", "Check if an email has been exposed in known data breaches");
        renderMenuItem("2", "Password Exposure Check", "Anonymously check if a password appears in breach databases");
        renderMenuItem("3", "Username Exposure Check", "Search for a username across breach sources");
        renderMenuItem("4", "Phone Number Exposure Check", "Search for a phone number in breach databases");
        renderMenuItem("5", "IP Reputation Check", "Check an IP address for abuse reports");
        renderMenuItem("6", "Domain Threat Intelligence", "Check a domain for malicious indicators in OTX");

        System.out.println();
        System.out.println(AnsiPainter.horizontalRule(TERM_WIDTH));
        renderMenuItem("0", "Exit", "Quit ShadowScan");
        System.out.println();
    }

    private void renderMenuItem(String key, String title, String description) {
        System.out.println(
                "  " + AnsiPainter.boldColor("[" + key + "]", AnsiPainter.NEON_GREEN)
                + " " + AnsiPainter.boldColor(title, AnsiPainter.BRIGHT_WHITE)
        );
        System.out.println(
                "      " + AnsiPainter.colorize(description, AnsiPainter.DIM_GRAY)
        );
    }

    // ─── Input Prompts ─────────────────────────────────────────────────

    public void renderModuleHeader(String moduleName) {
        setCurrentModule(moduleName);
        AnsiPainter.clearScreen();
        renderHeader();
        System.out.println();
        System.out.println("  " + AnsiPainter.boldColor("▸ " + moduleName, AnsiPainter.CYAN));
        System.out.println(AnsiPainter.horizontalRule(TERM_WIDTH));
        System.out.println();
    }

    public void renderInputPrompt(String prompt) {
        System.out.print("  ");
        System.out.print(AnsiPainter.CYAN);
        for (char c : prompt.toCharArray()) {
            System.out.print(c);
            try {
                Thread.sleep(25); // Hacker typing speed
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        System.out.print(" " + AnsiPainter.NEON_GREEN + "▸ " + AnsiPainter.RESET);
    }

    // ─── Results ───────────────────────────────────────────────────────

    public void renderResult(ScanResult result) {
        System.out.println();
        System.out.println(AnsiPainter.horizontalRule(TERM_WIDTH));
        System.out.println();

        // Status line
        System.out.println("  " + AnsiPainter.colorize("Status: ", AnsiPainter.CYAN)
                + AnsiPainter.colorize(result.getStatus(), AnsiPainter.BRIGHT_WHITE));

        // Source
        System.out.println("  " + AnsiPainter.colorize("Source: ", AnsiPainter.CYAN)
                + AnsiPainter.colorize(result.getRawSourceName(), AnsiPainter.DIM_GRAY));

        System.out.println();

        // Details
        List<String> details = result.getDetails();
        if (!details.isEmpty()) {
            System.out.println("  " + AnsiPainter.boldColor("Details:", AnsiPainter.CYAN));
            for (String detail : details) {
                String icon;
                String color;
                if (detail.startsWith("⚠")) {
                    icon = "  ⚠ ";
                    color = AnsiPainter.AMBER;
                    detail = detail.substring(1).trim();
                } else if (detail.startsWith("ℹ")) {
                    icon = "  ℹ ";
                    color = AnsiPainter.CYAN;
                    detail = detail.substring(1).trim();
                } else if (detail.startsWith("Recommendation:")) {
                    icon = "  ★ ";
                    color = AnsiPainter.YELLOW;
                } else {
                    icon = "  │ ";
                    color = AnsiPainter.WHITE;
                }
                System.out.println(AnsiPainter.colorize(icon, AnsiPainter.DIM_GRAY)
                        + AnsiPainter.colorize(detail, color));
            }
        }

        // Metadata (if any interesting keys)
        Map<String, String> meta = result.getMetadata();
        if (!meta.isEmpty() && meta.containsKey("abuseConfidenceScore")) {
            System.out.println();
            System.out.println("  " + AnsiPainter.boldColor("Metadata:", AnsiPainter.CYAN));
            for (Map.Entry<String, String> entry : meta.entrySet()) {
                System.out.println(AnsiPainter.colorize("  │ ", AnsiPainter.DIM_GRAY)
                        + AnsiPainter.colorize(entry.getKey() + ": ", AnsiPainter.DIM_GRAY)
                        + AnsiPainter.colorize(entry.getValue(), AnsiPainter.WHITE));
            }
        }

        System.out.println();
        System.out.println(AnsiPainter.horizontalRule(TERM_WIDTH));
    }

    // ─── Error Display ─────────────────────────────────────────────────

    public void renderError(String message) {
        System.out.println();
        System.out.println("  " + AnsiPainter.boldColor("✖ ERROR", AnsiPainter.RED)
                + AnsiPainter.colorize(": " + message, AnsiPainter.AMBER));
        System.out.println();
    }

    // ─── Utility ───────────────────────────────────────────────────────

    public void renderPressEnter() {
        System.out.println();
        System.out.print("  " + AnsiPainter.colorize("Press Enter to return to menu...", AnsiPainter.DIM_GRAY));
    }

    public void renderGoodbye() {
        new shadowscan.ui.animations.ShutdownAnimation().play("shutdown");
    }

    public void renderPasswordDisclaimer() {
        System.out.println("  " + AnsiPainter.colorize("Your password is hashed locally with Keccak-512.", AnsiPainter.DIM_GRAY));
        System.out.println("  " + AnsiPainter.colorize("Only a 10-character hash prefix is sent to the API.", AnsiPainter.DIM_GRAY));
        System.out.println("  " + AnsiPainter.colorize("The full password and hash never leave your machine.", AnsiPainter.DIM_GRAY));
        System.out.println();
    }

    public void renderPhoneDisclaimer() {
        System.out.println("  " + AnsiPainter.colorize("Note: Phone number data in breach databases is limited.", AnsiPainter.AMBER));
        System.out.println("  " + AnsiPainter.colorize("A clean result does not guarantee no exposure.", AnsiPainter.DIM_GRAY));
        System.out.println();
    }

    public void renderIpDisclaimer() {
        System.out.println("  " + AnsiPainter.colorize("This checks abuse reports, not breach exposure.", AnsiPainter.CYAN));
        System.out.println("  " + AnsiPainter.colorize("Data source: AbuseIPDB (community-reported abuse).", AnsiPainter.DIM_GRAY));
        System.out.println();
    }
}
