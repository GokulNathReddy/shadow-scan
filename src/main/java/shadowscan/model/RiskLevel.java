package shadowscan.model;

/**
 * Risk classification levels for scan results.
 * Each level carries a display name and ANSI color code for terminal rendering.
 * Used consistently across all 5 scan modules for uniform risk communication.
 */
public enum RiskLevel {

    SAFE("SAFE", "\033[38;5;46m"),           // Neon green
    CAUTION("CAUTION", "\033[38;5;214m"),     // Amber/orange
    EXPOSED("EXPOSED", "\033[38;5;226m"),     // Yellow
    CRITICAL("CRITICAL", "\033[38;5;196m"),   // Bright red
    ERROR("ERROR", "\033[38;5;240m");         // Dim gray for error states

    private final String displayName;
    private final String ansiColor;

    RiskLevel(String displayName, String ansiColor) {
        this.displayName = displayName;
        this.ansiColor = ansiColor;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getAnsiColor() {
        return ansiColor;
    }

    /**
     * Returns the verdict text wrapped in the appropriate ANSI color.
     */
    public String colorized() {
        return ansiColor + displayName + "\033[0m";
    }
}
