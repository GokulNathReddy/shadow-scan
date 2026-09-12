package shadowscan.ui;

/**
 * Interface for terminal animations.
 * Each implementation runs its animation in the calling thread
 * and should check the interrupted flag to stop gracefully.
 */
public interface ScanAnimation {

    /**
     * Play the animation. This method blocks until the animation completes
     * or is interrupted. Implementations should periodically check
     * Thread.currentThread().isInterrupted() to allow clean cancellation.
     *
     * @param context descriptive context for the animation (e.g., module name)
     */
    void play(String context);

    /**
     * @return a short name for this animation (for logging/debugging)
     */
    String getName();
}
