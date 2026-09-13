package shadowscan.core;

/**
 * Domain target for OSINT and Threat Intelligence lookups.
 */
public class DomainTarget implements ScanTarget {

    private final String domain;

    public DomainTarget(String domain) {
        if (domain == null || domain.trim().isEmpty()) {
            throw new IllegalArgumentException("Domain cannot be empty.");
        }
        String trimmed = domain.trim().toLowerCase();
        
        // Simple domain regex validation (e.g. example.com)
        if (!trimmed.matches("^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$")) {
            throw new IllegalArgumentException("Invalid domain format: " + trimmed);
        }
        this.domain = trimmed;
    }

    @Override
    public String getValue() {
        return domain;
    }

    @Override
    public String getType() {
        return "domain";
    }

    @Override
    public String getDisplayLabel() {
        return "Domain";
    }
}
