package shadowscan.ui;

/**
 * Low-level ANSI escape code helper.
 * Provides static methods for terminal colors, cursor control, and text styling.
 * All visual output should go through this class or TerminalRenderer.
 *
 * Color palette:
 *   Primary accent: Neon green (38;5;46)
 *   Info text: Cyan (36)
 *   Caution: Amber (38;5;214)
 *   Critical: Red (38;5;196)
 *   Boot noise: Dim gray (38;5;240)
 */
public final class AnsiPainter {

    // ─── Color Constants ───────────────────────────────────────────────
    public static final String NEON_GREEN  = "\033[38;5;46m";
    public static final String CYAN        = "\033[36m";
    public static final String AMBER       = "\033[38;5;214m";
    public static final String RED         = "\033[38;5;196m";
    public static final String YELLOW      = "\033[38;5;226m";
    public static final String DIM_GRAY    = "\033[38;5;240m";
    public static final String WHITE       = "\033[37m";
    public static final String BRIGHT_WHITE= "\033[97m";
    public static final String MAGENTA     = "\033[35m";
    public static final String DARK_GREEN  = "\033[38;5;22m";
    public static final String BG_BLACK    = "\033[40m";
    public static final String BG_GREEN    = "\033[48;5;22m";
    public static final String BG_RED      = "\033[48;5;52m";
    public static final String BG_DARK     = "\033[48;5;233m";

    // ─── Style Constants ───────────────────────────────────────────────
    public static final String BOLD        = "\033[1m";
    public static final String DIM         = "\033[2m";
    public static final String ITALIC      = "\033[3m";
    public static final String UNDERLINE   = "\033[4m";
    public static final String BLINK       = "\033[5m";
    public static final String REVERSE     = "\033[7m";
    public static final String RESET       = "\033[0m";

    private AnsiPainter() {}

    // ─── Text Styling ──────────────────────────────────────────────────

    public static String colorize(String text, String color) {
        return color + text + RESET;
    }

    public static String bold(String text) {
        return BOLD + text + RESET;
    }

    public static String dim(String text) {
        return DIM + text + RESET;
    }

    public static String boldColor(String text, String color) {
        return BOLD + color + text + RESET;
    }

    // ─── Cursor Control ────────────────────────────────────────────────

    public static void clearScreen() {
        System.out.print("\033[2J\033[H");
        System.out.flush();
    }

    public static void clearLine() {
        System.out.print("\033[2K\r");
        System.out.flush();
    }

    public static void moveCursor(int row, int col) {
        System.out.printf("\033[%d;%dH", row, col);
        System.out.flush();
    }

    public static void hideCursor() {
        System.out.print("\033[?25l");
        System.out.flush();
    }

    public static void showCursor() {
        System.out.print("\033[?25h");
        System.out.flush();
    }

    public static void moveUp(int lines) {
        System.out.printf("\033[%dA", lines);
        System.out.flush();
    }

    public static void saveCursor() {
        System.out.print("\033[s");
        System.out.flush();
    }

    public static void restoreCursor() {
        System.out.print("\033[u");
        System.out.flush();
    }

    // ─── Utility ───────────────────────────────────────────────────────

    /**
     * Repeat a character n times.
     */
    public static String repeat(char c, int n) {
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) sb.append(c);
        return sb.toString();
    }

    /**
     * Repeat a string n times.
     */
    public static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder(s.length() * n);
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }

    /**
     * Center-pad a string within a given width.
     */
    public static String center(String text, int width) {
        int padding = Math.max(0, width - text.length());
        int left = padding / 2;
        int right = padding - left;
        return repeat(' ', left) + text + repeat(' ', right);
    }

    /**
     * Create a horizontal rule.
     */
    public static String horizontalRule(int width) {
        return colorize(repeat('─', width), DIM_GRAY);
    }
}
