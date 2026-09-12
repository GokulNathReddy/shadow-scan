package shadowscan.core;

/**
 * Phone number scan target for breach lookups.
 * Coverage is limited — the UI should communicate this honestly.
 */
public class PhoneTarget implements ScanTarget {

    private final String phone;

    public PhoneTarget(String phone) {
        if (phone == null || phone.trim().isEmpty()) {
            throw new IllegalArgumentException("Phone number cannot be empty.");
        }
        // Strip spaces/dashes, keep + prefix and digits
        this.phone = phone.trim().replaceAll("[\\s\\-()]", "");
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
