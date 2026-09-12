package shadowscan.core;

/**
 * IP address scan target for reputation lookups.
 * Supports both IPv4 and IPv6 formats.
 */
public class IpTarget implements ScanTarget {

    private final String ip;

    public IpTarget(String ip) {
        if (ip == null || ip.trim().isEmpty()) {
            throw new IllegalArgumentException("IP address cannot be empty.");
        }
        String trimmed = ip.trim();
        if (!isValidIp(trimmed)) {
            throw new IllegalArgumentException("Invalid IP address format: " + trimmed);
        }
        this.ip = trimmed;
    }

    private boolean isValidIp(String ip) {
        // IPv4 pattern
        if (ip.matches("^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$")) {
            return true;
        }
        // Basic IPv6 pattern (simplified — accepts most common formats)
        if (ip.contains(":") && ip.matches("^[0-9a-fA-F:]+$")) {
            return true;
        }
        return false;
    }

    @Override
    public String getValue() {
        return ip;
    }

    @Override
    public String getType() {
        return "ip";
    }

    @Override
    public String getDisplayLabel() {
        return "IP Address";
    }
}
