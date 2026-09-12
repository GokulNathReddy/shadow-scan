package shadowscan.core;

/**
 * Represents a scan target — the input a user provides for a lookup.
 * Implemented by EmailTarget, PasswordTarget, UsernameTarget, PhoneTarget, IpTarget.
 *
 * This interface abstracts over the different types of identifiers that can
 * be checked against breach databases, allowing the ScanEngine and
 * BreachProvider to work polymorphically.
 */
public interface ScanTarget {

    /**
     * @return the raw input value (email address, password, username, phone, IP)
     */
    String getValue();

    /**
     * @return the target type identifier ("email", "password", "username", "phone", "ip")
     */
    String getType();

    /**
     * @return a human-readable label for UI rendering (e.g., "Email Address", "IP Address")
     */
    String getDisplayLabel();
}
