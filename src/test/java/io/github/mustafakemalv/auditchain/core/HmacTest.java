package io.github.mustafakemalv.auditchain.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class HmacTest {

    /** RFC 4231 test case 1: a published HMAC-SHA256 known-answer vector. */
    @Test
    void sha256_matchesRfc4231TestVector1() {
        byte[] key = new byte[20];
        Arrays.fill(key, (byte) 0x0b);
        byte[] data = "Hi There".getBytes(StandardCharsets.UTF_8);

        byte[] mac = Hmac.sha256(key, data);

        assertThat(Hmac.hex(mac))
                .isEqualTo("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    @Test
    void sha256_isDeterministic() {
        byte[] key = "key".getBytes(StandardCharsets.UTF_8);
        byte[] msg = "message".getBytes(StandardCharsets.UTF_8);

        assertThat(Hmac.sha256(key, msg)).isEqualTo(Hmac.sha256(key, msg));
    }

    @Test
    void hex_isLowercaseAndPreservesLeadingZeros() {
        byte[] bytes = HexFormat.of().parseHex("00ff10");
        assertThat(Hmac.hex(bytes)).isEqualTo("00ff10");
    }

    @Test
    void constantTimeEquals_trueForIdenticalArrays() {
        byte[] a = HexFormat.of().parseHex("deadbeef");
        byte[] b = HexFormat.of().parseHex("deadbeef");
        assertThat(Hmac.constantTimeEquals(a, b)).isTrue();
    }

    @Test
    void constantTimeEquals_falseForDifferentContent() {
        byte[] a = HexFormat.of().parseHex("deadbeef");
        byte[] b = HexFormat.of().parseHex("deadbeff");
        assertThat(Hmac.constantTimeEquals(a, b)).isFalse();
    }

    @Test
    void constantTimeEquals_falseForDifferentLength() {
        byte[] a = HexFormat.of().parseHex("dead");
        byte[] b = HexFormat.of().parseHex("deadbeef");
        assertThat(Hmac.constantTimeEquals(a, b)).isFalse();
    }

    @Test
    void constantTimeEquals_falseForNull() {
        assertThat(Hmac.constantTimeEquals(null, new byte[0])).isFalse();
        assertThat(Hmac.constantTimeEquals(new byte[0], null)).isFalse();
    }
}
