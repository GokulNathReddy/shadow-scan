package shadowscan.providers;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import shadowscan.core.BreachProvider;
import shadowscan.core.DomainTarget;
import shadowscan.core.RiskScorer;
import shadowscan.core.ScanTarget;
import shadowscan.model.RiskLevel;
import shadowscan.model.ScanResult;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

/**
 * BreachProvider for AlienVault OTX - Domain OSINT check.
 * Checks a domain for associated malicious pulses.
 * Public endpoint (no API key required for /general).
 */
public class AlienVaultDomainProvider implements BreachProvider {

    private static final String API_URL = "https://otx.alienvault.com/api/v1/indicators/domain/%s/general";
    private final HttpClient httpClient;

    public AlienVaultDomainProvider(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public boolean supports(ScanTarget target) {
        return target instanceof DomainTarget;
    }

    @Override
    public String getProviderName() {
        return "AlienVault OTX";
    }

    @Override
    public CompletableFuture<ScanResult> scan(ScanTarget target) {
        String domain = target.getValue();

        return CompletableFuture.supplyAsync(() -> {
            try {
                String encodedDomain = URLEncoder.encode(domain, StandardCharsets.UTF_8);
                String url = String.format(API_URL, encodedDomain);

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .timeout(Duration.ofSeconds(15))
                        .header("Accept", "application/json")
                        .GET()
                        .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() == 404) {
                    return buildSafeResult(domain);
                }

                if (response.statusCode() != 200) {
                    return ScanResult.error(getProviderName(), "API returned status " + response.statusCode());
                }

                JsonObject root = JsonParser.parseString(response.body()).getAsJsonObject();
                if (!root.has("pulse_info")) {
                    return buildSafeResult(domain);
                }

                JsonObject pulseInfo = root.getAsJsonObject("pulse_info");
                int count = pulseInfo.has("count") ? pulseInfo.get("count").getAsInt() : 0;

                if (count == 0) {
                    return buildSafeResult(domain);
                }

                RiskLevel level = count > 5 ? RiskLevel.CRITICAL : (count > 0 ? RiskLevel.CAUTION : RiskLevel.SAFE);

                return new ScanResult.Builder()
                        .riskLevel(level)
                        .status("Malicious Pulses Found")
                        .rawSourceName(getProviderName())
                        .addDetail("Found in " + count + " AlienVault OTX pulse(s)")
                        .addDetail("This domain has been associated with malicious activity in threat intelligence feeds.")
                        .addMetadata("pulseCount", String.valueOf(count))
                        .build();

            } catch (Exception e) {
                return ScanResult.error(getProviderName(), "AlienVault lookup failed: " + e.getMessage());
            }
        });
    }

    private ScanResult buildSafeResult(String domain) {
        return new ScanResult.Builder()
                .riskLevel(RiskLevel.SAFE)
                .status("No threat intelligence found")
                .rawSourceName(getProviderName())
                .addDetail("No malicious pulses found for this domain on AlienVault OTX.")
                .build();
    }
}
