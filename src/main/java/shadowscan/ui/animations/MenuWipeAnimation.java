package shadowscan.ui.animations;

import shadowscan.ui.AnsiPainter;
import shadowscan.ui.ScanAnimation;

/**
 * Menu transition wipe — a quick left-to-right color wipe across the screen
 * when moving between menu screens, so navigation feels animated.
 */
public class MenuWipeAnimation implements ScanAnimation {

    private static final int WIDTH = 80;
    private static final long WIPE_DELAY = 8;

    @Override
    public String getName() {
        return "Menu Wipe";
    }

    @Override
    public void play(String context) {
        try {
            AnsiPainter.hideCursor();
            int rows = 24;

            // Left-to-right wipe with green bar
            for (int col = 0; col < WIDTH; col += 3) {
                if (Thread.currentThread().isInterrupted()) return;

                for (int row = 1; row <= rows; row++) {
                    AnsiPainter.moveCursor(row, col + 1);
                    // Draw a thin vertical wipe bar
                    System.out.print(AnsiPainter.NEON_GREEN + "▌" + AnsiPainter.RESET);
                    // Clear what's behind the wipe
                    if (col > 0) {
                        AnsiPainter.moveCursor(row, col - 1);
                        System.out.print("  ");
                    }
                }
                System.out.flush();
                Thread.sleep(WIPE_DELAY);
            }

            // Final clear
            AnsiPainter.clearScreen();
            Thread.sleep(50);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            AnsiPainter.showCursor();
        }
    }
}
