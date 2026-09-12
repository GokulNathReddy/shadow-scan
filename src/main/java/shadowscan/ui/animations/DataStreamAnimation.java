package shadowscan.ui.animations;

import shadowscan.ui.AnsiPainter;
import shadowscan.ui.ScanAnimation;

import java.util.Random;

/**
 * Idle "data stream" animation — while waiting on a slow API response,
 * streams fake scrolling hex/log noise in a dim color in the background.
 *
 * IMPORTANT: This is purely cosmetic visual flavor. It does NOT represent
 * real network traffic, packet captures, or any actual data processing.
 * It's the equivalent of decorative background noise to keep the terminal
 * feeling alive during API waits.
 */
public class DataStreamAnimation implements ScanAnimation {

    private static final String HEX_CHARS = "0123456789abcdef";
    private static final long FRAME_DELAY = 40;

    @Override
    public String getName() {
        return "Data Stream";
    }

    @Override
    public void play(String context) {
        Random rng = new Random();
        AnsiPainter.hideCursor();
        int lineCount = 0;

        try {
            while (!Thread.currentThread().isInterrupted()) {
                StringBuilder line = new StringBuilder();

                // Timestamp-like prefix
                line.append(AnsiPainter.DIM_GRAY);
                line.append(String.format("  %02d:%02d:%02d.%03d ",
                        rng.nextInt(24), rng.nextInt(60), rng.nextInt(60), rng.nextInt(1000)));

                // Hex block
                line.append("│ ");
                for (int i = 0; i < 8; i++) {
                    for (int j = 0; j < 2; j++) {
                        line.append(HEX_CHARS.charAt(rng.nextInt(16)));
                    }
                    line.append(' ');
                }

                line.append("│ ");

                // ASCII representation (dots for non-printable)
                for (int i = 0; i < 8; i++) {
                    char c = (char) (rng.nextInt(94) + 33);
                    if (rng.nextInt(3) == 0) c = '.';
                    line.append(c);
                }

                line.append(AnsiPainter.RESET);

                System.out.println(line);
                lineCount++;

                // Every 8 lines, show the scanning status
                if (lineCount % 8 == 0) {
                    String[] spinChars = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"};
                    System.out.print(AnsiPainter.colorize(
                            "  " + spinChars[lineCount % spinChars.length] + " Awaiting API response for " + context + "...",
                            AnsiPainter.CYAN));
                    System.out.println();
                }

                // Keep output bounded — scroll naturally
                if (lineCount > 100) {
                    lineCount = 0;
                }

                Thread.sleep(FRAME_DELAY + rng.nextInt(30));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            AnsiPainter.showCursor();
        }
    }
}
