package shadowscan.ui.animations;

import shadowscan.ui.AnsiPainter;
import shadowscan.ui.ScanAnimation;
import shadowscan.model.RiskLevel;

import java.util.Random;

/**
 * Result reveal animation — verdict text (SAFE / EXPOSED / CRITICAL) prints
 * letter by letter in the color matching risk level, with a brief glitch-flicker
 * effect on high-severity results before it settles.
 */
public class ResultRevealAnimation implements ScanAnimation {

    private final RiskLevel riskLevel;

    public ResultRevealAnimation(RiskLevel riskLevel) {
        this.riskLevel = riskLevel;
    }

    @Override
    public String getName() {
        return "Result Reveal";
    }

    @Override
    public void play(String context) {
        String verdict = riskLevel.getDisplayName();
        String color = riskLevel.getAnsiColor();
        Random rng = new Random();

        try {
            AnsiPainter.hideCursor();

            // For high severity, do a glitch-flicker effect first
            if (riskLevel == RiskLevel.CRITICAL || riskLevel == RiskLevel.EXPOSED) {
                String glitchChars = "█▓▒░╬╫╪┼▪●■□";
                for (int flicker = 0; flicker < 6; flicker++) {
                    if (Thread.currentThread().isInterrupted()) return;
                    AnsiPainter.clearLine();
                    StringBuilder glitch = new StringBuilder("  ▸ VERDICT: ");
                    for (int i = 0; i < verdict.length(); i++) {
                        char gc = glitchChars.charAt(rng.nextInt(glitchChars.length()));
                        String flickerColor = rng.nextBoolean() ? AnsiPainter.RED : color;
                        glitch.append(AnsiPainter.BOLD).append(flickerColor).append(gc).append(AnsiPainter.RESET);
                    }
                    System.out.print(glitch);
                    System.out.flush();
                    Thread.sleep(60 + rng.nextInt(40));
                }
            }

            // Letter-by-letter reveal
            AnsiPainter.clearLine();
            System.out.print("  ▸ VERDICT: ");

            for (int i = 0; i < verdict.length(); i++) {
                if (Thread.currentThread().isInterrupted()) return;
                System.out.print(AnsiPainter.BOLD + color + verdict.charAt(i) + AnsiPainter.RESET);
                System.out.flush();
                Thread.sleep(80);
            }

            System.out.println();
            Thread.sleep(200);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            AnsiPainter.showCursor();
        }
    }
}
