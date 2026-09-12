package shadowscan.core;

/**
 * Username scan target for breach source lookups.
 */
public class UsernameTarget implements ScanTarget {

    private final String username;

    public UsernameTarget(String username) {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be empty.");
        }
        this.username = username.trim();
    }

    @Override
    public String getValue() {
        return username;
    }

    @Override
    public String getType() {
        return "username";
    }

    @Override
    public String getDisplayLabel() {
        return "Username";
    }
}
