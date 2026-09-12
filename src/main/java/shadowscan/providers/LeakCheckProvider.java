package shadowscan.providers;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import shadowscan.core.BreachProvider;
import shadowscan.core.PhoneTarget;
import shadowscan.core.RiskScorer;
import shadowscan.core.ScanTarget;
import shadowscan.core.UsernameTarget;
import shadowscan.model.RiskLevel;
import shadowscan.model.ScanResult;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * BreachProvider for the LeakCheck public API.
 * Handles both username and phone number lookups.
 *
 * The public API (no auth) returns only breach source names and exposed
 * data categories — never the actual leaked data itself.
 *
 * Endpoint: GET https://leakcheck.io/api/public?check={query}
 * Rate limit: 1 request per second.
 */
public class LeakCheckProvider implements BreachProvider {

    private static final String API_URL = "https://leakcheck.io/api/public?check=";

    private final HttpClient httpClient;

    public LeakCheckProvider(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public boolean supports(ScanTarget target) {
        return target instanceof UsernameTarget || target instanceof PhoneTarget;
    }

    @Override
    public String getProviderName() {
        return "LeakCheck";
    }

    @Override
    public CompletableFuture<ScanResult> scan(ScanTarget target) {
        String query = target.getValue();
        boolean isPhone = target instanceof PhoneTarget;

        return CompletableFuture.supplyAsync(() -> {
            try {
                String encodedQuery = URLEncoder.encode(query, StandardCharsets.UTF_8);

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(API_URL + encodedQuery))
                        .timeout(Duration.ofSeconds(15))
                        .header("Accept", "application/json")
                        .GET()
                        .build();

                HttpResponse<String> response = httpClient.send(request,
                        HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() == 404) {
                    return buildSafeResult(target, isPhone);
                }

                if (response.statusCode() == 429) {
                    return ScanResult.error(getProviderName(),
                            "Rate limited by LeakCheck API (max 1 req/sec). Please wait and try again.");
                }

                if (response.statusCode() != 200) {
                    return ScanResult.error(getProviderName(),
                            "API returned status " + response.statusCode());
                }

                String body = response.body().trim();

                // The public API can return different formats:
                // Success with results: JSON array of objects with "source" and "fields"
                // No results: {"success":false,"msg":"Not found"} or empty array
                // Also possible: {"result":[ ... ]} wrapper

                List<String> sources = new ArrayList<>();
                List<String> fields = new ArrayList<>();

                JsonElement rootElement = JsonParser.parseString(body);

                if (rootElement.isJsonObject()) {
                    JsonObject rootObj = rootElement.getAsJsonObject();

                    // Check for error/not-found responses
                    if (rootObj.has("success") && !rootObj.get("success").getAsBoolean()) {
                        return buildSafeResult(target, isPhone);
                    }
                    if (rootObj.has("error")) {
                        return ScanResult.error(getProviderName(), rootObj.get("error").getAsString());
                    }

                    // Check for "result" array wrapper
                    if (rootObj.has("result") && rootObj.get("result").isJsonArray()) {
                        parseResultArray(rootObj.getAsJsonArray("result"), sources, fields);
                    }
                } else if (rootElement.isJsonArray()) {
                    parseResultArray(rootElement.getAsJsonArray(), sources, fields);
                }

                if (sources.isEmpty()) {
                    return buildSafeResult(target, isPhone);
                }

                RiskLevel level = RiskScorer.scoreLeakCheck(sources.size());

                ScanResult.Builder builder = new ScanResult.Builder()
                        .riskLevel(level)
                        .status("Found in breach sources")
                        .rawSourceName(getProviderName())
                        .addDetail("Found in " + sources.size() + " breach source(s)")
                        .addDetail("Sources: " + String.join(", ", sources))
                        .addMetadata("sourceCount", String.valueOf(sources.size()))
                        .addMetadata("queryType", isPhone ? "phone" : "username");

                if (!fields.isEmpty()) {
                    builder.addDetail("Exposed data categories: " + String.join(", ", fields));
                }

                if (isPhone) {
                    builder.addDetail("⚠ Limited coverage — phone number data in breach databases is thinner than email data.");
                }

                return builder.build();

            } catch (java.net.http.HttpTimeoutException e) {
                return ScanResult.error(getProviderName(),
                        "Request timed out. The API may be slow or unreachable.");
            } catch (Exception e) {
                return ScanResult.error(getProviderName(),
                        "Lookup failed: " + e.getMessage());
            }
        });
    }

    private void parseResultArray(JsonArray arr, List<String> sources, List<String> fields) {
        for (JsonElement el : arr) {
            if (el.isJsonObject()) {
                JsonObject obj = el.getAsJsonObject();
                if (obj.has("source")) {
                    String source = obj.get("source").getAsString();
                    if (!sources.contains(source)) {
                        sources.add(source);
                    }
                }
                // "fields" can be an array of exposed data type strings
                if (obj.has("fields") && obj.get("fields").isJsonArray()) {
                    for (JsonElement f : obj.getAsJsonArray("fields")) {
                        String field = f.getAsString();
                        if (!fields.contains(field)) {
                            fields.add(field);
                        }
                    }
                }
            }
        }
    }

    private ScanResult buildSafeResult(ScanTarget target, boolean isPhone) {
        ScanResult.Builder builder = new ScanResult.Builder()
                .riskLevel(RiskLevel.SAFE)
                .status("Not found in breach sources")
                .rawSourceName(getProviderName())
                .addDetail("This " + target.getDisplayLabel().toLowerCase() + " was not found in LeakCheck's public breach database.");

        if (isPhone) {
            builder.addDetail("Note: Phone number coverage in breach databases is limited. A clean result here does not guarantee no exposure.");
        }

        return builder.build();
    }
}
