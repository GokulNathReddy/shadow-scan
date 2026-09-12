package shadowscan.providers;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import shadowscan.core.BreachProvider;
import shadowscan.core.PasswordTarget;
import shadowscan.core.RiskScorer;
import shadowscan.core.ScanTarget;
import shadowscan.model.RiskLevel;
import shadowscan.model.ScanResult;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

/**
 * BreachProvider for password exposure checking via XposedOrNot's
 * anonymous k-anonymity API.
 *
 * SECURITY MODEL (k-anonymity):
 * ─────────────────────────────
 * 1. The password is hashed locally using SHA3 Keccak-512 (Bouncy Castle).
 * 2. Only the FIRST 10 HEX CHARACTERS of the hash are sent to the API.
 * 3. The full password and full hash MUST NEVER leave the client.
 *
 * This ensures:
 *   - The API server never sees the actual password.
 *   - The API server never sees the full hash (which could be brute-forced).
 *   - The 10-char prefix maps to many possible passwords, preserving anonymity.
 *
 * The full hash is computed in a local variable, the prefix is extracted,
 * and the full hash is never stored in any field, transmitted, or logged.
 *
 * Endpoint: GET https://passwords.xposedornot.com/api/v1/pass/anon/{hash_prefix}
 */
public class XposedOrNotPasswordProvider implements BreachProvider {

    private static final String API_URL = "https://passwords.xposedornot.com/api/v1/pass/anon/";

    private final HttpClient httpClient;

    public XposedOrNotPasswordProvider(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public boolean supports(ScanTarget target) {
        return target instanceof PasswordTarget;
    }

    @Override
    public String getProviderName() {
        return "XposedOrNot (Password)";
    }

    @Override
    public CompletableFuture<ScanResult> scan(ScanTarget target) {
        // SECURITY: The password value is accessed here, hashed immediately,
        // and only the 10-char prefix is used from this point forward.
        // The full password string and full hash never leave this method's scope
        // and are never transmitted over the network.
        String password = target.getValue();

        return CompletableFuture.supplyAsync(() -> {
            try {
                // Step 1: Hash the password locally with Keccak-512
                // SECURITY: Full hash is a local variable only — never stored in a field,
                // never transmitted, never logged. Only the 10-char prefix leaves this scope.
                String hashPrefix = computeKeccak512Prefix(password);
                // At this point, `password` is still in scope but we never use it again.
                // The full hash existed only inside computeKeccak512Prefix() and is now garbage.

                // Step 2: Send only the prefix to the API (k-anonymity)
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(API_URL + hashPrefix))
                        .timeout(Duration.ofSeconds(15))
                        .GET()
                        .build();

                HttpResponse<String> response = httpClient.send(request,
                        HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() == 404) {
                    return buildSafeResult();
                }

                if (response.statusCode() == 429) {
                    return ScanResult.error(getProviderName(),
                            "Rate limited. Please wait a moment and try again.");
                }

                if (response.statusCode() != 200) {
                    return ScanResult.error(getProviderName(),
                            "API returned status " + response.statusCode());
                }

                // Parse response
                JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();

                if (json.has("Error")) {
                    return buildSafeResult();
                }

                if (!json.has("SearchPassAnon")) {
                    return buildSafeResult();
                }

                JsonObject result = json.getAsJsonObject("SearchPassAnon");

                long count = 0;
                if (result.has("count")) {
                    try {
                        count = Long.parseLong(result.get("count").getAsString());
                    } catch (NumberFormatException e) {
                        count = result.get("count").getAsLong();
                    }
                }

                boolean isInWordlist = result.has("wordlist") && result.get("wordlist").getAsInt() == 1;
                String charBreakdown = result.has("char") ? result.get("char").getAsString() : "N/A";

                RiskLevel level = RiskScorer.scorePassword(count, isInWordlist);

                ScanResult.Builder builder = new ScanResult.Builder()
                        .riskLevel(level)
                        .status("Password exposure detected")
                        .rawSourceName(getProviderName())
                        .addDetail("This password has been seen " + formatCount(count) + " time(s) in known data breaches.")
                        .addDetail("Character composition: " + formatCharBreakdown(charBreakdown))
                        .addMetadata("exposureCount", String.valueOf(count))
                        .addMetadata("hashPrefix", hashPrefix);

                if (isInWordlist) {
                    builder.addDetail("⚠ This password appears in known cracking wordlists.");
                }

                if (level == RiskLevel.CRITICAL || level == RiskLevel.EXPOSED) {
                    builder.addDetail("Recommendation: Change this password immediately wherever it is used.");
                }

                return builder.build();

            } catch (java.net.http.HttpTimeoutException e) {
                return ScanResult.error(getProviderName(),
                        "Request timed out. The API may be slow or unreachable.");
            } catch (Exception e) {
                return ScanResult.error(getProviderName(),
                        "Password check failed: " + e.getMessage());
            }
        });
    }

    /**
     * Computes Keccak-512 hash of the password and returns only the first 10 hex chars.
     *
     * SECURITY: The full 128-character hex hash is computed as a local variable
     * and immediately substring'd to 10 chars. The full hash is never returned,
     * stored, or transmitted. This is the k-anonymity guarantee.
     */
    private String computeKeccak512Prefix(String password) {
        Keccak.Digest512 keccak = new Keccak.Digest512();
        byte[] hashBytes = keccak.digest(password.getBytes(StandardCharsets.UTF_8));

        // Convert to hex string (full hash is 128 hex chars for Keccak-512)
        StringBuilder fullHash = new StringBuilder();
        for (byte b : hashBytes) {
            fullHash.append(String.format("%02x", b));
        }

        // SECURITY: Return ONLY the first 10 characters.
        // The full hash (fullHash variable) goes out of scope here and is garbage collected.
        // It is never stored in any field, never returned, and never transmitted.
        return fullHash.substring(0, 10);
    }

    private ScanResult buildSafeResult() {
        return new ScanResult.Builder()
                .riskLevel(RiskLevel.SAFE)
                .status("Password not found in breaches")
                .rawSourceName(getProviderName())
                .addDetail("This password was not found in known data breaches indexed by XposedOrNot.")
                .addDetail("Note: This doesn't guarantee the password is strong — only that it hasn't appeared in indexed breaches.")
                .build();
    }

    private String formatCount(long count) {
        if (count >= 1_000_000) return String.format("%.1fM", count / 1_000_000.0);
        if (count >= 1_000) return String.format("%.1fK", count / 1_000.0);
        return String.valueOf(count);
    }

    private String formatCharBreakdown(String charStr) {
        // Input format: "D:6;A:0;S:0;L:6"
        // Output: "6 digits, 0 letters, 0 special chars, length 6"
        try {
            String[] parts = charStr.split(";");
            StringBuilder sb = new StringBuilder();
            for (String part : parts) {
                String[] kv = part.split(":");
                if (kv.length == 2) {
                    switch (kv[0].trim()) {
                        case "D": sb.append(kv[1]).append(" digits, "); break;
                        case "A": sb.append(kv[1]).append(" letters, "); break;
                        case "S": sb.append(kv[1]).append(" special chars, "); break;
                        case "L": sb.append("length ").append(kv[1]); break;
                    }
                }
            }
            return sb.toString();
        } catch (Exception e) {
            return charStr;
        }
    }
}
