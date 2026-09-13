package shadowscan.core;

/**
 * Phone number scan target for breach lookups.
 * Coverage is limited — the UI should communicate this honestly.
 */
public class PhoneTarget implements ScanTarget {

    private final String phone;

    public PhoneTarget(String phone) {
        if (phone == null) {
            throw new IllegalArgumentException("Phone number cannot be null.");
        }
        // Strip spaces, dashes, parens, and plus signs
        String cleaned = phone.trim().replaceAll("[\\s\\-()+]", "");
        if (cleaned.isEmpty() || !cleaned.matches("^\\d+$")) {
            throw new IllegalArgumentException("Invalid phone number format: " + phone);
        }
        this.phone = cleaned;
    }

    @Override
    public String getValue() {
        return phone;
    }

    @Override
    public String getType() {
        return "phone";
    }

    @Override
    public String getDisplayLabel() {
        return "Phone Number";
    }
}
