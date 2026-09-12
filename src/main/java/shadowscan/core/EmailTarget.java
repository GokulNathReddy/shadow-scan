package shadowscan.core;

/**
 * Email address scan target with basic format validation.
 */
public class EmailTarget implements ScanTarget {

    private final String email;

    public EmailTarget(String email) {
        if (email == null || !email.matches("^[\\w.%+-]+@[\\w.-]+\\.[a-zA-Z]{2,}$")) {
            throw new IllegalArgumentException("Invalid email format: " + email);
        }
        this.email = email.trim().toLowerCase();
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
