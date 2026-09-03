package io.github.mustafakemalv.auditchain.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.mustafakemalv.auditchain.core.AuditRecord;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

class InMemoryAuditStoreTest {

    /**
     * A stand-in hash with the shape a real one has: 64 lowercase hex characters, derived from a
     * label so each one is distinct and stable across runs.
     */
    private static String hash(String label) {
        return String.format("%064x", Math.abs((long) label.hashCode()) + 1);
    }

    private static ChainedRecord chained(long sequence, String previousHash, String hash) {
        AuditRecord record = new AuditRecord(sequence, Instant.EPOCH, "actor", "action", null, null, Map.of());
        return ChainedRecord.currentFormat(record, previousHash, hash);
    }

    @Test
    void lastIsEmptyWhenNoRecords() {
        assertThat(new InMemoryAuditStore().last()).isEmpty();
    }

    @Test
    void appendMakesRecordTheHead() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        ChainedRecord first = chained(0, hash("gen"), hash("h0"));
        ChainedRecord second = chained(1, hash("h0"), hash("h1"));

        store.append(first);
        store.append(second);

        assertThat(store.last()).contains(second);
        assertThat(store.count()).isEqualTo(2);
    }

    @Test
    void findAllReturnsRecordsInAppendOrder() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        ChainedRecord first = chained(0, hash("gen"), hash("h0"));
        ChainedRecord second = chained(1, hash("h0"), hash("h1"));
        store.append(first);
        store.append(second);

        assertThat(store.findAll()).containsExactly(first, second);
    }

    @Test
    void findAllReturnsACopy() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        store.append(chained(0, hash("gen"), hash("h0")));

        store.findAll().clear();

        assertThat(store.count()).isEqualTo(1);
    }

    @Test
    void refusesARepeatedSequenceSoTheChainCannotFork() {
        // Two chains over one store used to race here and append duplicate sequence numbers, which
        // verification then reported forever as tampering that never happened.
        InMemoryAuditStore store = new InMemoryAuditStore();
        store.append(chained(0L, hash("prev"), hash("hash-0")));

        assertThatThrownBy(() -> store.append(chained(0L, hash("prev"), hash("hash-0"))))
                .isInstanceOf(AuditStoreException.class);
        assertThatThrownBy(() -> store.append(chained(0L, hash("hash-0"), hash("other"))))
                .isInstanceOf(AuditStoreException.class);
        assertThat(store.count()).isEqualTo(1L);
    }

    @Test
    void refusesASequenceThatGoesBackwards() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        store.append(chained(0L, hash("prev"), hash("hash-0")));
        store.append(chained(1L, hash("hash-0"), hash("hash-1")));

        assertThatThrownBy(() -> store.append(chained(1L, hash("hash-1"), hash("hash-1b"))))
                .isInstanceOf(AuditStoreException.class);
        assertThat(store.count()).isEqualTo(2L);
    }

    @Test
    void findRangeReturnsASliceInSequenceOrder() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        for (long i = 0; i < 10; i++) {
            store.append(chained(i, hash("p" + i), hash("h" + i)));
        }

        assertThat(store.findRange(3L, 4).stream().map(r -> r.record().sequence()).toList())
                .containsExactly(3L, 4L, 5L, 6L);
        assertThat(store.findRange(9L, 5)).hasSize(1);
        assertThat(store.findRange(10L, 5)).isEmpty();
        assertThatThrownBy(() -> store.findRange(0L, 0))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
