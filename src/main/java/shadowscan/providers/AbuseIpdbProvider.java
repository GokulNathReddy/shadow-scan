package shadowscan.providers;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import shadowscan.core.BreachProvider;
import shadowscan.core.IpTarget;
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
 * BreachProvider for the AbuseIPDB API — IP reputation checking.
 *
 * IMPORTANT DISTINCTION: This checks ABUSE REPORTS, not breach exposure.
 * The UI labels this "IP Reputation" (not "IP Leak Check") to accurately
 * reflect what the data means.
 *
 * Endpoint: GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90
 * Auth: API key via "Key" header, read from ABUSEIPDB_KEY environment variable.
 * NEVER hardcode the API key in source code.
 */
public class AbuseIpdbProvider implements BreachProvider {

    private static final String API_URL = "https://api.abuseipdb.com/api/v2/check";
    private static final String ENV_KEY_NAME = "ABUSEIPDB_KEY";

    private final HttpClient httpClient;

    public AbuseIpdbProvider(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public boolean supports(ScanTarget target) {
        return target instanceof IpTarget;
    }

    @Override
    public String getProviderName() {
        return "AbuseIPDB";
    }

    @Override
    public CompletableFuture<ScanResult> scan(ScanTarget target) {
        String ip = target.getValue();

        return CompletableFuture.supplyAsync(() -> {
            // Read API key from environment variable — NEVER hardcoded
            String apiKey = System.getenv(ENV_KEY_NAME);
            if (apiKey == null || apiKey.trim().isEmpty()) {
                return new ScanResult.Builder()
                        .riskLevel(RiskLevel.ERROR)
                        .status("API key not configured")
                        .rawSourceName(getProviderName())
                        .addDetail("The ABUSEIPDB_KEY environment variable is not set.")
                        .addDetail("To use IP Reputation checking:")
                        .addDetail("  1. Sign up for a free API key at https://www.abuseipdb.com/account/api")
                        .addDetail("  2. Set the environment variable: set ABUSEIPDB_KEY=your_key_here")
                        .addDetail("  3. Restart ShadowScan")
                        .build();
            }

            try {
                String encodedIp = URLEncoder.encode(ip, StandardCharsets.UTF_8);
                String url = API_URL + "?ipAddress=" + encodedIp + "&maxAgeInDays=90&verbose";

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .timeout(Duration.ofSeconds(15))
                        .header("Key", apiKey)
                        .header("Accept", "application/json")
                        .GET()
                        .build();

                HttpResponse<String> response = httpClient.send(request,
                        HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() == 401) {
                    return ScanResult.error(getProviderName(),
                            "Invalid API key. Please check your ABUSEIPDB_KEY environment variable.");
                }

                if (response.statusCode() == 429) {
                    return ScanResult.error(getProviderName(),
                            "Rate limited by AbuseIPDB. Free tier allows 1000 checks/day.");
                }

                if (response.statusCode() == 422) {
                    return ScanResult.error(getProviderName(),
                            "Invalid IP address format. Please check your input.");
                }

                if (response.statusCode() != 200) {
                    return ScanResult.error(getProviderName(),
                            "API returned status " + response.statusCode());
                }

                // Parse the response
                JsonObject root = JsonParser.parseString(response.body()).getAsJsonObject();

                if (!root.has("data")) {
                    return ScanResult.error(getProviderName(), "Unexpected response format.");
                }

                JsonObject data = root.getAsJsonObject("data");

                int abuseScore = data.has("abuseConfidenceScore") ?
                        data.get("abuseConfidenceScore").getAsInt() : 0;
                int totalReports = data.has("totalReports") ?
                        data.get("totalReports").getAsInt() : 0;
                String countryCode = data.has("countryCode") && !data.get("countryCode").isJsonNull() ?
                        data.get("countryCode").getAsString() : "N/A";
                String isp = data.has("isp") && !data.get("isp").isJsonNull() ?
                        data.get("isp").getAsString() : "N/A";
                String domain = data.has("domain") && !data.get("domain").isJsonNull() ?
                        data.get("domain").getAsString() : "N/A";
                String usageType = data.has("usageType") && !data.get("usageType").isJsonNull() ?
                        data.get("usageType").getAsString() : "N/A";
                boolean isTor = data.has("isTor") && data.get("isTor").getAsBoolean();
                boolean isWhitelisted = data.has("isWhitelisted") &&
                        !data.get("isWhitelisted").isJsonNull() &&
                        data.get("isWhitelisted").getAsBoolean();
                String lastReportedAt = data.has("lastReportedAt") &&
                        !data.get("lastReportedAt").isJsonNull() ?
                        data.get("lastReportedAt").getAsString() : "Never";

                RiskLevel level = RiskScorer.scoreIpReputation(abuseScore, totalReports);

                ScanResult.Builder builder = new ScanResult.Builder()
                        .riskLevel(level)
                        .rawSourceName(getProviderName())
                        .addMetadata("ipAddress", ip)
                        .addMetadata("abuseConfidenceScore", String.valueOf(abuseScore))
                        .addMetadata("totalReports", String.valueOf(totalReports));

                // Build contextual details
                builder.addDetail("Abuse Confidence Score: " + abuseScore + "%");
                builder.addDetail("Total Reports (last 90 days): " + totalReports);
                builder.addDetail("Country: " + countryCode);
                builder.addDetail("ISP: " + isp);
                builder.addDetail("Domain: " + domain);
                builder.addDetail("Usage Type: " + usageType);

                if (isTor) {
                    builder.addDetail("⚠ This IP is a known Tor exit node");
                }
                if (isWhitelisted) {
                    builder.addDetail("ℹ This IP is whitelisted (generally trusted)");
                }
                if (!"Never".equals(lastReportedAt)) {
                    builder.addDetail("Last Reported: " + lastReportedAt);
                }

                if (abuseScore == 0 && totalReports == 0) {
                    builder.status("Clean reputation");
                    builder.addDetail("This IP has no abuse reports in the last 90 days.");
                } else {
                    builder.status("Abuse reports found");
                }

                return builder.build();

            } catch (java.net.http.HttpTimeoutException e) {
                return ScanResult.error(getProviderName(),
                        "Request timed out. The API may be slow or unreachable.");
            } catch (Exception e) {
                return ScanResult.error(getProviderName(),
                        "IP reputation check failed: " + e.getMessage());
            }
        });
    }
}
