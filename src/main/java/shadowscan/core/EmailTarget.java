package shadowscan.core;

/**
 * Email address scan target with basic format validation.
 */
public class EmailTarget implements ScanTarget {

    private final String email;

    public EmailTarget(String email) {
        if (email == null) {
            throw new IllegalArgumentException("Email cannot be null");
        }
        String trimmed = email.trim().toLowerCase();
        if (!trimmed.matches("^[\\w.%+-]+@[\\w.-]+\\.[a-zA-Z]{2,}$")) {
            throw new IllegalArgumentException("Invalid email format: " + trimmed);
        }
        this.email = trimmed;
    }

    @Override
    public String getValue() {
        return email;
    }

    @Override
    public String getType() {
        return "email";
    }

    @Override
    public String getDisplayLabel() {
        return "Email Address";
    }
}
