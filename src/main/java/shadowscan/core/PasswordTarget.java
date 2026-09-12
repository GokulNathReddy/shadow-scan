package shadowscan.core;

/**
 * Password scan target.
 * The raw password is held only long enough to hash it — the provider
 * MUST hash locally and discard. See XposedOrNotPasswordProvider.
 */
public class PasswordTarget implements ScanTarget {

    private final String password;

    public PasswordTarget(String password) {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty.");
        }
        this.password = password;
    }

    @Override
    public String getValue() {
        return password;
    }

    @Override
    public String getType() {
        return "password";
    }

    @Override
    public String getDisplayLabel() {
        return "Password";
    }
}
