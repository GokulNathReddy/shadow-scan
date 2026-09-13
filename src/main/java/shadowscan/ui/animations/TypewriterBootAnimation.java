package shadowscan.ui.animations;

import shadowscan.ui.AnsiPainter;
import shadowscan.ui.ScanAnimation;

/**
 * Typewriter boot sequence animation — ASCII "SHADOWSCAN" banner types itself
 * out character by character with a fake boot log underneath.
 *
 * Note: The boot log messages are cosmetic flavor text only. They do not
 * imply real security operations or capabilities that aren't present.
 */
public class TypewriterBootAnimation implements ScanAnimation {

    private static final String[] BANNER = {
        "  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗   ███████╗ ██████╗ █████╗ ███╗   ██╗",
        "  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║   ██╔════╝██╔════╝██╔══██╗████╗  ██║",
        "  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║   ███████╗██║     ███████║██╔██╗ ██║",
        "  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║   ╚════██║██║     ██╔══██║██║╚██╗██║",
        "  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝   ███████║╚██████╗██║  ██║██║ ╚████║",
        "  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
    };

    private static final String[] BOOT_LOG = {
        "[OK] Initializing scan modules...",
        "[OK] Loading breach databases...",
        "[OK] Establishing API connections...",
        "[OK] Keccak-512 hash engine ready",
        "[OK] ANSI terminal capabilities detected",
        "[OK] Animation subsystem loaded",
        "[>>] ShadowScan v1.0 ready"
    };

    @Override
    public String getName() {
        return "Typewriter Boot";
    }

    @Override
    public void play(String context) {
        AnsiPainter.clearScreen();
        AnsiPainter.hideCursor();

        try {
            System.out.println();

            // Type out the banner character by character
            for (String line : BANNER) {
                for (int i = 0; i < line.length(); i++) {
                    if (Thread.currentThread().isInterrupted()) return;
                    char c = line.charAt(i);
                    if (c != ' ') {
                        System.out.print(AnsiPainter.BOLD + AnsiPainter.NEON_GREEN + c + AnsiPainter.RESET);
                    } else {
                        System.out.print(c);
                    }
                    // Variable speed for realistic typewriter feel
                    if (c != ' ' && i % 3 == 0) {
                        Thread.sleep(1);
                    }
                }
                System.out.println();
            }

            System.out.println();
            System.out.println(AnsiPainter.colorize("  ─── Terminal Breach Intelligence Tool ───", AnsiPainter.CYAN));
            System.out.println();
            Thread.sleep(200);

            // Boot log with progressive reveal
            for (String logLine : BOOT_LOG) {
                if (Thread.currentThread().isInterrupted()) return;

                String prefix;
                String rest;
                if (logLine.startsWith("[>>]")) {
                    prefix = AnsiPainter.boldColor("[>>]", AnsiPainter.NEON_GREEN);
                    rest = AnsiPainter.boldColor(logLine.substring(4), AnsiPainter.NEON_GREEN);
                } else {
                    prefix = AnsiPainter.colorize("[OK]", AnsiPainter.NEON_GREEN);
                    rest = AnsiPainter.colorize(logLine.substring(4), AnsiPainter.DIM_GRAY);
                }

                // Type out with delay
                System.out.print("  " + prefix);
                for (char c : rest.toCharArray()) {
                    System.out.print(c);
                }
                System.out.println();
                Thread.sleep(120 + (long)(Math.random() * 80));
            }

            System.out.println();
            Thread.sleep(500);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            AnsiPainter.showCursor();
        }
    }
}
