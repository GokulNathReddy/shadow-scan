package shadowscan.ui.animations;

import shadowscan.ui.AnsiPainter;
import shadowscan.ui.ScanAnimation;

/**
 * Sweeping radar-line spinner animation.
 * A line sweeps around a circle, creating a radar/sonar effect.
 */
public class RadarSpinnerAnimation implements ScanAnimation {

    private static final String[] FRAMES = {
        "◜ ", " ◝", " ◞", "◟ "
    };
    private static final String[] SWEEP = {
        "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█", "▉", "▊", "▋", "▌", "▍", "▎", "▏", " "
    };
    private static final long FRAME_DELAY = 100;

    @Override
    public String getName() {
        return "Radar Sweep";
    }

    @Override
    public void play(String context) {
        AnsiPainter.hideCursor();
        int frame = 0;
        try {
            while (!Thread.currentThread().isInterrupted()) {
                String radarChar = AnsiPainter.boldColor(FRAMES[frame % FRAMES.length], AnsiPainter.NEON_GREEN);
                String sweep = AnsiPainter.colorize(SWEEP[frame % SWEEP.length], AnsiPainter.DARK_GREEN);

                AnsiPainter.clearLine();
                System.out.print("  " + radarChar + sweep + " "
                        + AnsiPainter.colorize("Scanning " + context + "...", AnsiPainter.CYAN)
                        + "  " + AnsiPainter.dim(buildRadarBar(frame)));
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

    private String buildRadarBar(int frame) {
        StringBuilder bar = new StringBuilder("[");
        int width = 20;
        int pos = frame % (width * 2);
        if (pos >= width) pos = width * 2 - pos - 1;

        for (int i = 0; i < width; i++) {
            if (i == pos) {
                bar.append(AnsiPainter.NEON_GREEN).append("█").append(AnsiPainter.RESET);
            } else if (Math.abs(i - pos) == 1) {
                bar.append(AnsiPainter.NEON_GREEN).append("▓").append(AnsiPainter.RESET);
            } else if (Math.abs(i - pos) == 2) {
                bar.append(AnsiPainter.DARK_GREEN).append("░").append(AnsiPainter.RESET);
            } else {
                bar.append(AnsiPainter.DIM_GRAY).append("·").append(AnsiPainter.RESET);
            }
        }
        bar.append(AnsiPainter.DIM_GRAY).append("]").append(AnsiPainter.RESET);
        return bar.toString();
    }
}
