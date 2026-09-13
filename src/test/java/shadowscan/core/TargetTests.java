package shadowscan.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TargetTests {

    @Test
    void testIpTarget_Valid() {
        IpTarget target = new IpTarget("192.168.1.1");
        assertEquals("192.168.1.1", target.getValue());
    }

    @Test
    void testIpTarget_Invalid() {
        assertThrows(IllegalArgumentException.class, () -> new IpTarget("not_an_ip"));
        assertThrows(IllegalArgumentException.class, () -> new IpTarget("256.256.256.256"));
    }

    @Test
    void testPhoneTarget_StripsSymbols() {
        PhoneTarget target = new PhoneTarget(" +1 (555) 123-4567 ");
        // Ensure + is also stripped based on our latest fix
        assertEquals("15551234567", target.getValue());
    }

    @Test
    void testEmailTarget_Valid() {
        EmailTarget target = new EmailTarget(" test@example.com ");
        assertEquals("test@example.com", target.getValue());
    }
}
