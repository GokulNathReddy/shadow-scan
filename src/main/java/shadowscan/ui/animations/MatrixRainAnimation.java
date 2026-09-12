package shadowscan.ui.animations;

import shadowscan.ui.AnsiPainter;
import shadowscan.ui.ScanAnimation;

import java.util.Random;

/**
 * Matrix-rain intro animation — green falling character columns
 * for ~1.5 seconds on startup before the main menu renders.
 */
public class MatrixRainAnimation implements ScanAnimation {

    private static final int COLS = 80;
    private static final int ROWS = 24;
    private static final String CHARS = "ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ0123456789ABCDEF";
    private static final long DURATION_MS = 1500;
    private static final long FRAME_DELAY = 50;

    @Override
    public String getName() {
        return "Matrix Rain";
    }

    @Override
    public void play(String context) {
        Random rng = new Random();
        AnsiPainter.clearScreen();
        AnsiPainter.hideCursor();

        // Track the "drop" position for each column
        int[] drops = new int[COLS];
        for (int i = 0; i < COLS; i++) {
            drops[i] = rng.nextInt(ROWS) - ROWS; // Start at random offsets
        }

        long startTime = System.currentTimeMillis();

        try {
            while (System.currentTimeMillis() - startTime < DURATION_MS &&
                   !Thread.currentThread().isInterrupted()) {

                StringBuilder frame = new StringBuilder();
                frame.append("\033[H"); // Move to top-left

                for (int row = 0; row < ROWS; row++) {
                    for (int col = 0; col < COLS; col++) {
                        int dropPos = drops[col];

                        if (row == dropPos) {
                            // Head of the drop — bright white/green
                            char c = CHARS.charAt(rng.nextInt(CHARS.length()));
                            frame.append(AnsiPainter.BOLD).append(AnsiPainter.BRIGHT_WHITE)
                                 .append(c).append(AnsiPainter.RESET);
                        } else if (row == dropPos - 1) {
                            // Just behind the head — bright green
                            char c = CHARS.charAt(rng.nextInt(CHARS.length()));
                            frame.append(AnsiPainter.BOLD).append(AnsiPainter.NEON_GREEN)
                                 .append(c).append(AnsiPainter.RESET);
                        } else if (row < dropPos && row > dropPos - 8) {
                            // Trail — fading green
                            char c = CHARS.charAt(rng.nextInt(CHARS.length()));
                            int fade = dropPos - row;
                            if (fade < 4) {
                                frame.append(AnsiPainter.NEON_GREEN).append(c).append(AnsiPainter.RESET);
                            } else {
                                frame.append(AnsiPainter.DARK_GREEN).append(c).append(AnsiPainter.RESET);
                            }
                        } else {
                            frame.append(' ');
                        }
                    }
                    if (row < ROWS - 1) frame.append('\n');
                }

                System.out.print(frame);
                System.out.flush();

                // Advance drops
                for (int i = 0; i < COLS; i++) {
                    drops[i]++;
                    if (drops[i] > ROWS + 8) {
                        drops[i] = rng.nextInt(ROWS / 2) * -1;
                    }
                    // Random speed variation
                    if (rng.nextInt(10) < 2) {
                        drops[i]++;
                    }
                }

                Thread.sleep(FRAME_DELAY);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            AnsiPainter.showCursor();
            AnsiPainter.clearScreen();
        }
    }
}
