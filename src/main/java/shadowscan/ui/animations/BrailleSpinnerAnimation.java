package shadowscan.ui.animations;

import shadowscan.ui.AnsiPainter;
import shadowscan.ui.ScanAnimation;

/**
 * Braille-dot spinner animation for scanning state.
 * Uses Unicode braille characters for a smooth rotation effect.
 */
public class BrailleSpinnerAnimation implements ScanAnimation {

    private static final String[] FRAMES = {
        "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"
    };
    private static final long FRAME_DELAY = 80;

    @Override
    public String getName() {
        return "Braille Spinner";
    }

    @Override
    public void play(String context) {
        AnsiPainter.hideCursor();
        int frame = 0;
        try {
            while (!Thread.currentThread().isInterrupted()) {
                String spinner = AnsiPainter.boldColor(FRAMES[frame % FRAMES.length], AnsiPainter.NEON_GREEN);
                AnsiPainter.clearLine();
                System.out.print("  " + spinner + AnsiPainter.colorize(" Scanning " + context + "...", AnsiPainter.CYAN));
                System.out.flush();
                frame++;
                Thread.sleep(FRAME_DELAY);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            AnsiPainter.clearLine();
            AnsiPainter.showCursor();
        }
    }
}
