package shadowscan.ui.animations;

import shadowscan.ui.AnsiPainter;
import shadowscan.ui.ScanAnimation;

import java.util.Random;

/**
 * Progress bar with glitch-flicker effect.
 * The bar fills up but occasionally "glitches" with random characters,
 * creating a cyberpunk aesthetic.
 */
public class GlitchProgressAnimation implements ScanAnimation {

    private static final int BAR_WIDTH = 30;
    private static final String GLITCH_CHARS = "█▓▒░╬╫╪┼╳▪▫●○";
    private static final long FRAME_DELAY = 80;

    @Override
    public String getName() {
        return "Glitch Progress";
    }

    @Override
    public void play(String context) {
        AnsiPainter.hideCursor();
        Random rng = new Random();
        int progress = 0;

        try {
            while (!Thread.currentThread().isInterrupted()) {
                AnsiPainter.clearLine();
                StringBuilder bar = new StringBuilder();
                bar.append(AnsiPainter.DIM_GRAY).append("  [").append(AnsiPainter.RESET);

                boolean glitching = rng.nextInt(8) == 0; // Occasional glitch

                for (int i = 0; i < BAR_WIDTH; i++) {
                    int displayProgress = (progress / 3) % BAR_WIDTH;
                    if (i <= displayProgress) {
                        if (glitching && rng.nextInt(4) == 0) {
                            // Glitch character
                            char gc = GLITCH_CHARS.charAt(rng.nextInt(GLITCH_CHARS.length()));
                            bar.append(AnsiPainter.RED).append(gc).append(AnsiPainter.RESET);
                        } else {
                            bar.append(AnsiPainter.NEON_GREEN).append("█").append(AnsiPainter.RESET);
                        }
                    } else if (i == displayProgress + 1) {
                        bar.append(AnsiPainter.NEON_GREEN).append("▒").append(AnsiPainter.RESET);
                    } else {
                        bar.append(AnsiPainter.DIM_GRAY).append("─").append(AnsiPainter.RESET);
                    }
                }

                bar.append(AnsiPainter.DIM_GRAY).append("]").append(AnsiPainter.RESET);

                String statusText = glitching ?
                    AnsiPainter.colorize(" ▌▌ SCANNING ▐▐", AnsiPainter.RED) :
                    AnsiPainter.colorize(" Scanning " + context + "...", AnsiPainter.CYAN);

                System.out.print(bar.toString() + statusText);
                System.out.flush();

                progress++;
                Thread.sleep(glitching ? FRAME_DELAY / 2 : FRAME_DELAY);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            AnsiPainter.clearLine();
            AnsiPainter.showCursor();
        }
    }
}
