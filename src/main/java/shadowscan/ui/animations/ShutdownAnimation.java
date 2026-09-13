package shadowscan.ui.animations;

import shadowscan.ui.AnsiPainter;
import shadowscan.ui.ScanAnimation;

/**
 * A cinematic shutdown sequence simulating a secure terminal disconnection.
 */
public class ShutdownAnimation implements ScanAnimation {

    @Override
    public String getName() {
        return "System Shutdown";
    }

    @Override
    public void play(String context) {
        AnsiPainter.hideCursor();
        System.out.println();
        
        String[] shutdownSequence = {
            "Initiating secure disconnect...",
            "Purging local cache...",
            "Severing API connections...",
            "Overwriting memory sectors...",
            "Connection closed."
        };

        try {
            for (String step : shutdownSequence) {
                System.out.print("  " + AnsiPainter.CYAN + "[*] " + AnsiPainter.DIM_GRAY + step);
                Thread.sleep(300);
                System.out.print("\r  " + AnsiPainter.NEON_GREEN + "[+] " + AnsiPainter.WHITE + step + "\n");
                Thread.sleep(150);
            }
            
            System.out.println();
            
            // "Power down" flicker effect
            String goodbye = "  SHADOWSCAN OFFLINE";
            for (int i = 0; i < 5; i++) {
                System.out.print("\r" + AnsiPainter.boldColor(goodbye, AnsiPainter.RED));
                Thread.sleep(50);
                System.out.print("\r" + AnsiPainter.colorize(goodbye, AnsiPainter.DIM_GRAY));
                Thread.sleep(50);
            }
            System.out.print("\r" + AnsiPainter.boldColor(goodbye, AnsiPainter.DIM_GRAY) + "\n\n");
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            AnsiPainter.showCursor();
        }
    }
}
