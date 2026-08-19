package io.github.mustafakemalv.auditchain.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AuditRecordTest {

    @Test
    void rejectsNullTimestamp() {
        assertThatThrownBy(() -> new AuditRecord(1L, null, "a", "act", null, null, Map.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsNullAction() {
        assertThatThrownBy(() -> new AuditRecord(1L, Instant.EPOCH, "a", null, null, null, Map.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsNullDetailKey() {
        Map<String, String> details = new HashMap<>();
        details.put(null, "v");
        assertThatThrownBy(() -> new AuditRecord(1L, Instant.EPOCH, "a", "act", null, null, details))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void nullDetailsBecomesEmptyMap() {
        AuditRecord record = new AuditRecord(1L, Instant.EPOCH, "a", "act", null, null, null);
        assertThat(record.details()).isEmpty();
    }

    @Test
    void detailsAreDefensivelyCopied() {
        Map<String, String> mutable = new HashMap<>();
        mutable.put("k", "v");
        AuditRecord record = new AuditRecord(1L, Instant.EPOCH, "a", "act", null, null, mutable);

        mutable.put("injected", "x");

        assertThat(record.details()).containsOnlyKeys("k");
    }

    @Test
    void detailsAreUnmodifiable() {
        AuditRecord record = new AuditRecord(1L, Instant.EPOCH, "a", "act", null, null, Map.of("k", "v"));
        assertThatThrownBy(() -> record.details().put("x", "y"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void timestampIsTruncatedToMilliseconds() {
        Instant withNanos = Instant.ofEpochSecond(100, 123_456_789);
        AuditRecord record = new AuditRecord(1L, withNanos, "a", "act", null, null, Map.of());
        assertThat(record.timestamp()).isEqualTo(Instant.ofEpochSecond(100, 123_000_000));
    }
}
