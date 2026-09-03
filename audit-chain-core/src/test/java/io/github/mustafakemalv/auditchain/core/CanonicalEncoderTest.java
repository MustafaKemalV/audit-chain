package io.github.mustafakemalv.auditchain.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CanonicalEncoderTest {

    private static byte[] encode(AuditRecord record) {
        return CanonicalEncoder.encode(record, CanonicalEncoder.currentFormatVersion());
    }

    private static AuditRecord record(String actor, String action, String resourceType,
            String resourceId, Map<String, String> details) {
        return new AuditRecord(1L, Instant.ofEpochSecond(1_700_000_000L, 123), actor, action,
                resourceType, resourceId, details);
    }

    @Test
    void encodingIsDeterministic() {
        AuditRecord a = record("alice", "login", "user", "42", Map.of("ip", "1.2.3.4"));
        AuditRecord b = record("alice", "login", "user", "42", Map.of("ip", "1.2.3.4"));
        assertThat(encode(a)).isEqualTo(encode(b));
    }

    @Test
    void mapIterationOrderDoesNotChangeEncoding() {
        Map<String, String> ordered = new LinkedHashMap<>();
        ordered.put("a", "1");
        ordered.put("b", "2");
        ordered.put("c", "3");
        Map<String, String> shuffled = new LinkedHashMap<>();
        shuffled.put("c", "3");
        shuffled.put("a", "1");
        shuffled.put("b", "2");

        assertThat(encode(record("x", "y", null, null, ordered)))
                .isEqualTo(encode(record("x", "y", null, null, shuffled)));
    }

    @Test
    void nullFieldDiffersFromEmptyString() {
        byte[] withNull = encode(record(null, "y", null, null, Map.of()));
        byte[] withEmpty = encode(record("", "y", null, null, Map.of()));
        assertThat(withNull).isNotEqualTo(withEmpty);
    }

    @Test
    void fieldShiftingCannotCollide() {
        // Without length prefixes, "alice"+"delete" and "alicedelete"+"" would concatenate to the
        // same bytes. Length prefixing must keep them distinct so an attacker cannot shift content
        // between fields while preserving the hash.
        byte[] split = encode(record("alice", "delete", null, null, Map.of()));
        byte[] shifted = encode(record("alicedelete", "", null, null, Map.of()));
        assertThat(split).isNotEqualTo(shifted);
    }

    @Test
    void detailsEntriesCannotCollideAcrossKeyValueBoundary() {
        // {"ab":"c"} vs {"a":"bc"} must differ — length prefixing keeps the key/value split.
        byte[] one = encode(record("a", "act", null, null, Map.of("ab", "c")));
        byte[] two = encode(record("a", "act", null, null, Map.of("a", "bc")));
        assertThat(one).isNotEqualTo(two);
    }

    @Test
    void differentSequenceProducesDifferentBytes() {
        AuditRecord first = new AuditRecord(1L, Instant.ofEpochSecond(100), "a", "act", null, null, Map.of());
        AuditRecord second = new AuditRecord(2L, Instant.ofEpochSecond(100), "a", "act", null, null, Map.of());
        assertThat(encode(first)).isNotEqualTo(encode(second));
    }

    @Test
    void differentTimestampProducesDifferentBytes() {
        // AuditRecord truncates to millis, so distinctness is at millisecond granularity
        AuditRecord first = new AuditRecord(1L, Instant.ofEpochMilli(100), "a", "act", null, null, Map.of());
        AuditRecord second = new AuditRecord(1L, Instant.ofEpochMilli(101), "a", "act", null, null, Map.of());
        assertThat(encode(first)).isNotEqualTo(encode(second));
    }

    @Test
    void detailsValueChangeProducesDifferentBytes() {
        byte[] one = encode(record("a", "act", null, null, Map.of("k", "v1")));
        byte[] two = encode(record("a", "act", null, null, Map.of("k", "v2")));
        assertThat(one).isNotEqualTo(two);
    }

    @Test
    void theEncodingFormatIsFrozen() {
        // The literal below is the whole point of this test: it pins the byte layout of format
        // version 1. If a change to the encoder makes this fail, every record already written under
        // version 1 has just become unverifiable. The fix is never to update the literal; it is to
        // leave version 1 alone and introduce version 2.
        AuditRecord record = new AuditRecord(1L, Instant.ofEpochMilli(1_700_000_000_123L),
                "alice", "login", "user", "42", Map.of("ip", "1.2.3.4"));

        assertThat(HexFormat.of().formatHex(encode(record)))
                .isEqualTo("00000001"                     // format version
                        + "0000000000000001"              // sequence
                        + "000000006553f100"              // timestamp, epoch seconds
                        + "0754d4c0"                      // timestamp, nanos
                        + "00000005616c696365"            // actor "alice"
                        + "000000056c6f67696e"            // action "login"
                        + "0000000475736572"              // resourceType "user"
                        + "000000023432"                  // resourceId "42"
                        + "00000001"                      // details entry count
                        + "000000026970"                  // key "ip"
                        + "00000007312e322e332e34");      // value "1.2.3.4"
    }

    @Test
    void theFormatVersionIsTheFirstFieldEncoded() {
        AuditRecord record = record("alice", "login", "user", "42", Map.of());
        byte[] encoded = encode(record);

        assertThat(HexFormat.of().formatHex(Arrays.copyOf(encoded, 4))).isEqualTo("00000001");
    }

    @Test
    void refusesToEncodeUnderAVersionThisBuildDoesNotWrite() {
        AuditRecord record = record("alice", "login", "user", "42", Map.of());

        assertThatThrownBy(() -> CanonicalEncoder.encode(record, 2))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsupported format version");
        assertThatThrownBy(() -> CanonicalEncoder.encode(null, CanonicalEncoder.currentFormatVersion()))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
