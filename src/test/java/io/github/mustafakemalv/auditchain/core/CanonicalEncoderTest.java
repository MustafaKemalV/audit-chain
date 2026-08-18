package io.github.mustafakemalv.auditchain.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CanonicalEncoderTest {

    private static AuditRecord record(String actor, String action, String resourceType,
            String resourceId, Map<String, String> details) {
        return new AuditRecord(1L, Instant.ofEpochSecond(1_700_000_000L, 123), actor, action,
                resourceType, resourceId, details);
    }

    @Test
    void encodingIsDeterministic() {
        AuditRecord a = record("alice", "login", "user", "42", Map.of("ip", "1.2.3.4"));
        AuditRecord b = record("alice", "login", "user", "42", Map.of("ip", "1.2.3.4"));
        assertThat(CanonicalEncoder.encode(a)).isEqualTo(CanonicalEncoder.encode(b));
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

        assertThat(CanonicalEncoder.encode(record("x", "y", null, null, ordered)))
                .isEqualTo(CanonicalEncoder.encode(record("x", "y", null, null, shuffled)));
    }

    @Test
    void nullFieldDiffersFromEmptyString() {
        byte[] withNull = CanonicalEncoder.encode(record(null, "y", null, null, Map.of()));
        byte[] withEmpty = CanonicalEncoder.encode(record("", "y", null, null, Map.of()));
        assertThat(withNull).isNotEqualTo(withEmpty);
    }

    @Test
    void fieldShiftingCannotCollide() {
        // Without length prefixes, "alice"+"delete" and "alicedelete"+"" would concatenate to the
        // same bytes. Length prefixing must keep them distinct so an attacker cannot shift content
        // between fields while preserving the hash.
        byte[] split = CanonicalEncoder.encode(record("alice", "delete", null, null, Map.of()));
        byte[] shifted = CanonicalEncoder.encode(record("alicedelete", "", null, null, Map.of()));
        assertThat(split).isNotEqualTo(shifted);
    }

    @Test
    void detailsEntriesCannotCollideAcrossKeyValueBoundary() {
        // {"ab":"c"} vs {"a":"bc"} must differ — length prefixing keeps the key/value split.
        byte[] one = CanonicalEncoder.encode(record("a", "act", null, null, Map.of("ab", "c")));
        byte[] two = CanonicalEncoder.encode(record("a", "act", null, null, Map.of("a", "bc")));
        assertThat(one).isNotEqualTo(two);
    }

    @Test
    void differentSequenceProducesDifferentBytes() {
        AuditRecord first = new AuditRecord(1L, Instant.ofEpochSecond(100), "a", "act", null, null, Map.of());
        AuditRecord second = new AuditRecord(2L, Instant.ofEpochSecond(100), "a", "act", null, null, Map.of());
        assertThat(CanonicalEncoder.encode(first)).isNotEqualTo(CanonicalEncoder.encode(second));
    }

    @Test
    void differentTimestampNanosProduceDifferentBytes() {
        AuditRecord first = new AuditRecord(1L, Instant.ofEpochSecond(100, 0), "a", "act", null, null, Map.of());
        AuditRecord second = new AuditRecord(1L, Instant.ofEpochSecond(100, 1), "a", "act", null, null, Map.of());
        assertThat(CanonicalEncoder.encode(first)).isNotEqualTo(CanonicalEncoder.encode(second));
    }

    @Test
    void detailsValueChangeProducesDifferentBytes() {
        byte[] one = CanonicalEncoder.encode(record("a", "act", null, null, Map.of("k", "v1")));
        byte[] two = CanonicalEncoder.encode(record("a", "act", null, null, Map.of("k", "v2")));
        assertThat(one).isNotEqualTo(two);
    }
}
