package shadowscan.providers;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import shadowscan.core.BreachProvider;
import shadowscan.core.EmailTarget;
import shadowscan.core.RiskScorer;
import shadowscan.core.ScanTarget;
import shadowscan.model.RiskLevel;
import shadowscan.model.ScanResult;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * BreachProvider implementation for the XposedOrNot API.
 * Handles email breach checking with optional detailed analytics.
 *
 * Endpoints:
 *   Quick check: GET https://api.xposedornot.com/v1/check-email/{email}
 *   Analytics:    GET https://api.xposedornot.com/v1/breach-analytics?email={email}
 */
public class XposedOrNotProvider implements BreachProvider {

    private static final String CHECK_URL = "https://api.xposedornot.com/v1/check-email/";
    private static final String ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics?email=";

    private final HttpClient httpClient;
    private final Gson gson;

    public XposedOrNotProvider(HttpClient httpClient) {
        this.httpClient = httpClient;
        this.gson = new Gson();
    }

    @Override
    public boolean supports(ScanTarget target) {
        return target instanceof EmailTarget;
    }

    @Override
    public String getProviderName() {
        return "XposedOrNot";
    }

    @Override
    public CompletableFuture<ScanResult> scan(ScanTarget target) {
        String email = target.getValue();

        return CompletableFuture.supplyAsync(() -> {
            try {
                // Step 1: Quick breach check
                HttpRequest checkReq = HttpRequest.newBuilder()
                        .uri(URI.create(CHECK_URL + email))
                        .timeout(Duration.ofSeconds(15))
                        .GET()
                        .build();

                HttpResponse<String> checkResp = httpClient.send(checkReq,
                        HttpResponse.BodyHandlers.ofString());

                if (checkResp.statusCode() == 404) {
                    return buildSafeResult();
                }

                if (checkResp.statusCode() == 429) {
                    return ScanResult.error(getProviderName(),
                            "Rate limited by XposedOrNot API. Please wait a moment and try again.");
                }

                if (checkResp.statusCode() != 200) {
                    return ScanResult.error(getProviderName(),
                            "API returned status " + checkResp.statusCode());
                }

                // Parse quick check response
                JsonObject checkJson = JsonParser.parseString(checkResp.body()).getAsJsonObject();

                // Check for "Error" field indicating not found
                if (checkJson.has("Error")) {
                    return buildSafeResult();
                }

                List<String> breachNames = new ArrayList<>();
                if (checkJson.has("breaches") && checkJson.get("breaches").isJsonArray()) {
                    JsonArray outerArray = checkJson.getAsJsonArray("breaches");
                    for (JsonElement outer : outerArray) {
                        if (outer.isJsonArray()) {
                            for (JsonElement inner : outer.getAsJsonArray()) {
                                breachNames.add(inner.getAsString());
                            }
                        }
                    }
                }

                if (breachNames.isEmpty()) {
                    return buildSafeResult();
                }

                // Step 2: Fetch detailed analytics for breached email
                return fetchAnalytics(email, breachNames);

            } catch (java.net.http.HttpTimeoutException e) {
                return ScanResult.error(getProviderName(),
                        "Request timed out. The API may be slow or unreachable.");
            } catch (Exception e) {
                return ScanResult.error(getProviderName(),
                        "Lookup failed: " + e.getMessage());
            }
        });
    }

    private ScanResult fetchAnalytics(String email, List<String> breachNames) {
        try {
            HttpRequest analyticsReq = HttpRequest.newBuilder()
                    .uri(URI.create(ANALYTICS_URL + email))
                    .timeout(Duration.ofSeconds(15))
                    .GET()
                    .build();

            HttpResponse<String> analyticsResp = httpClient.send(analyticsReq,
                    HttpResponse.BodyHandlers.ofString());

            int riskScore = -1;
            String riskLabel = "";
            List<String> details = new ArrayList<>();
            List<String> exposedDataTypes = new ArrayList<>();

            details.add("Found in " + breachNames.size() + " breach(es)");
            details.add("Breached sites: " + String.join(", ", breachNames));

            if (analyticsResp.statusCode() == 200) {
                JsonObject analytics = JsonParser.parseString(analyticsResp.body()).getAsJsonObject();

                // Extract risk score from BreachMetrics
                if (analytics.has("BreachMetrics") && !analytics.get("BreachMetrics").isJsonNull()) {
                    JsonObject metrics = analytics.getAsJsonObject("BreachMetrics");

                    if (metrics.has("risk") && metrics.get("risk").isJsonArray()) {
                        JsonArray riskArr = metrics.getAsJsonArray("risk");
                        if (riskArr.size() > 0) {
                            JsonObject riskObj = riskArr.get(0).getAsJsonObject();
                            riskScore = riskObj.has("risk_score") ? riskObj.get("risk_score").getAsInt() : -1;
                            riskLabel = riskObj.has("risk_label") ? riskObj.get("risk_label").getAsString() : "";
                        }
                    }

                    // Extract password strength info
                    if (metrics.has("passwords_strength") && metrics.get("passwords_strength").isJsonArray()) {
                        JsonArray pwArr = metrics.getAsJsonArray("passwords_strength");
                        if (pwArr.size() > 0) {
                            JsonObject pw = pwArr.get(0).getAsJsonObject();
                            int plainText = pw.has("PlainText") ? pw.get("PlainText").getAsInt() : 0;
                            int easyToCrack = pw.has("EasyToCrack") ? pw.get("EasyToCrack").getAsInt() : 0;
                            if (plainText > 0) details.add("⚠ " + plainText + " breach(es) stored passwords in plain text");
                            if (easyToCrack > 0) details.add("⚠ " + easyToCrack + " breach(es) used easily crackable hashes");
                        }
                    }
                }

                // Extract exposed data types from ExposedBreaches
                if (analytics.has("ExposedBreaches") && !analytics.get("ExposedBreaches").isJsonNull()) {
                    JsonObject exposed = analytics.getAsJsonObject("ExposedBreaches");
                    if (exposed.has("breaches_details") && exposed.get("breaches_details").isJsonArray()) {
                        JsonArray breachDetails = exposed.getAsJsonArray("breaches_details");
                        for (JsonElement el : breachDetails) {
                            JsonObject bd = el.getAsJsonObject();
                            if (bd.has("xposed_data")) {
                                String xData = bd.get("xposed_data").getAsString();
                                for (String dtype : xData.split(";")) {
                                    String trimmed = dtype.trim();
                                    if (!trimmed.isEmpty() && !exposedDataTypes.contains(trimmed)) {
                                        exposedDataTypes.add(trimmed);
                                    }
                                }
                            }
                        }
                    }
                }

                if (!exposedDataTypes.isEmpty()) {
                    details.add("Exposed data types: " + String.join(", ", exposedDataTypes));
                }
                if (!riskLabel.isEmpty()) {
                    details.add("XposedOrNot risk assessment: " + riskLabel + " (score: " + riskScore + "/10)");
                }
            }

            RiskLevel level = RiskScorer.scoreEmail(breachNames.size(), riskScore);

            return new ScanResult.Builder()
                    .riskLevel(level)
                    .status("Breach data found")
                    .rawSourceName(getProviderName())
                    .details(details)
                    .addMetadata("email", email)
                    .addMetadata("breachCount", String.valueOf(breachNames.size()))
                    .build();

        } catch (Exception e) {
            // Analytics failed but we still have the quick check data
            RiskLevel level = RiskScorer.scoreEmail(breachNames.size(), -1);
            List<String> details = new ArrayList<>();
            details.add("Found in " + breachNames.size() + " breach(es)");
            details.add("Breached sites: " + String.join(", ", breachNames));
            details.add("(Detailed analytics unavailable: " + e.getMessage() + ")");

            return new ScanResult.Builder()
                    .riskLevel(level)
                    .status("Breach data found (partial)")
                    .rawSourceName(getProviderName())
                    .details(details)
                    .build();
        }
    }

    private ScanResult buildSafeResult() {
        return new ScanResult.Builder()
                .riskLevel(RiskLevel.SAFE)
                .status("No breaches found")
                .rawSourceName(getProviderName())
                .addDetail("This email was not found in any known data breaches indexed by XposedOrNot.")
                .build();
    }
}
