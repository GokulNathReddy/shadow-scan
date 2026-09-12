package shadowscan.core;

import shadowscan.model.ScanResult;
import java.util.concurrent.CompletableFuture;

/**
 * Strategy pattern interface for breach/exposure data providers.
 *
 * Each implementation wraps a specific external API (XposedOrNot, LeakCheck,
 * AbuseIPDB) and normalizes its response into a ScanResult. The ScanEngine
 * selects the appropriate provider at runtime based on the ScanTarget type.
 *
 * Design decision: This is the Strategy pattern — each provider encapsulates
 * a different "algorithm" (API integration) behind a common interface.
 * New data sources can be added by implementing this interface without
 * modifying the engine or UI.
 */
public interface BreachProvider {

    /**
     * Execute a scan against this provider's API.
     * Returns a CompletableFuture so the UI can animate while the HTTP
     * request is in flight — the network call must never block the animation thread.
     *
     * @param target the scan target to check
     * @return a future that resolves to a normalized ScanResult
     */
    CompletableFuture<ScanResult> scan(ScanTarget target);

    /**
     * Runtime type check — does this provider handle the given target type?
     *
     * @param target the scan target to check
     * @return true if this provider can process the target
     */
    boolean supports(ScanTarget target);

    /**
     * @return human-readable provider name for attribution (e.g., "XposedOrNot")
     */
    String getProviderName();
}
