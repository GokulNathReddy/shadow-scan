package shadowscan.ui.animations;

import shadowscan.ui.AnsiPainter;
import shadowscan.ui.ScanAnimation;

import java.util.Random;

/**
 * A short processing effect played immediately after the user submits input.
 * Simulates data being encrypted/decrypted before the actual scan starts.
 */
public class MatrixProcessingAnimation implements ScanAnimation {

    private static final String CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%&*+=-<>?";

    @Override
    public String getName() {
        return "Matrix Processing";
    }

    @Override
    public void play(String context) {
        Random rng = new Random();
        int width = Math.min(context.length() + 20, 50);

        AnsiPainter.hideCursor();
        
        System.out.println();
        System.out.print("  ");

        try {
            // Rapidly flicker random characters
            for (int i = 0; i < 15; i++) {
                System.out.print("\r  " + AnsiPainter.CYAN + "[ENCRYPTING] " + AnsiPainter.NEON_GREEN);
                for (int j = 0; j < width; j++) {
                    System.out.print(CHARS.charAt(rng.nextInt(CHARS.length())));
                }
                System.out.flush();
                Thread.sleep(40);
            }
            
            // "Lock in" the effect
            System.out.print("\r  " + AnsiPainter.CYAN + "[LOCKED IN]  " + AnsiPainter.BRIGHT_WHITE);
            for (int j = 0; j < width; j++) {
                System.out.print("-");
            }
            System.out.println(AnsiPainter.RESET);
            Thread.sleep(300);
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            AnsiPainter.showCursor();
        }
    }
}
