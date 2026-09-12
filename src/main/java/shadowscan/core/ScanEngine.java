package shadowscan.core;

import shadowscan.model.ScanResult;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Orchestrator that wires ScanTargets to the appropriate BreachProvider
 * and executes scans asynchronously. Owns the shared HttpClient instance.
 */
public class ScanEngine {

    private final List<BreachProvider> providers;
    private final HttpClient httpClient;

    public ScanEngine() {
        this.providers = new ArrayList<>();
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /**
     * Register a provider with the engine.
     */
    public void registerProvider(BreachProvider provider) {
        providers.add(provider);
    }

    /**
     * Find the first provider that supports the given target and execute the scan.
     * Returns a CompletableFuture so the caller can animate while waiting.
     *
     * @param target the scan target
     * @return future resolving to a ScanResult
     */
    public CompletableFuture<ScanResult> execute(ScanTarget target) {
        for (BreachProvider provider : providers) {
            if (provider.supports(target)) {
                return provider.scan(target);
            }
        }
        return CompletableFuture.completedFuture(
                ScanResult.error("None", "No provider found for target type: " + target.getType())
        );
    }

    /**
     * @return the shared HttpClient for providers to use
     */
    public HttpClient getHttpClient() {
        return httpClient;
    }
}
