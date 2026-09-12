package shadowscan.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Normalized result object returned by all BreachProvider implementations.
 * Regardless of which API was queried, the result is always presented
 * through this uniform structure — keeping the UI layer decoupled from
 * API-specific response formats.
 */
public class ScanResult {

    private final RiskLevel riskLevel;
    private final String status;
    private final List<String> details;
    private final String rawSourceName;
    private final Map<String, String> metadata;

    private ScanResult(Builder builder) {
        this.riskLevel = builder.riskLevel;
        this.status = builder.status;
        this.details = builder.details;
        this.rawSourceName = builder.rawSourceName;
        this.metadata = builder.metadata;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public String getStatus() {
        return status;
    }

    public List<String> getDetails() {
        return details;
    }

    public String getRawSourceName() {
        return rawSourceName;
    }

    public Map<String, String> getMetadata() {
        return metadata;
    }

    /**
     * Convenience factory for error results with styled messaging.
     */
    public static ScanResult error(String source, String message) {
        return new Builder()
                .riskLevel(RiskLevel.ERROR)
                .status("Error")
                .rawSourceName(source)
                .addDetail(message)
                .build();
    }

    /**
     * Builder pattern for clean, readable construction of ScanResult objects.
     */
    public static class Builder {
        private RiskLevel riskLevel = RiskLevel.SAFE;
        private String status = "Unknown";
        private List<String> details = new ArrayList<>();
        private String rawSourceName = "Unknown";
        private Map<String, String> metadata = new LinkedHashMap<>();

        public Builder riskLevel(RiskLevel riskLevel) {
            this.riskLevel = riskLevel;
            return this;
        }

        public Builder status(String status) {
            this.status = status;
            return this;
        }

        public Builder details(List<String> details) {
            this.details = new ArrayList<>(details);
            return this;
        }

        public Builder addDetail(String detail) {
            this.details.add(detail);
            return this;
        }

        public Builder rawSourceName(String rawSourceName) {
            this.rawSourceName = rawSourceName;
            return this;
        }

        public Builder metadata(Map<String, String> metadata) {
            this.metadata = new LinkedHashMap<>(metadata);
            return this;
        }

        public Builder addMetadata(String key, String value) {
            this.metadata.put(key, value);
            return this;
        }

        public ScanResult build() {
            return new ScanResult(this);
        }
    }
}
