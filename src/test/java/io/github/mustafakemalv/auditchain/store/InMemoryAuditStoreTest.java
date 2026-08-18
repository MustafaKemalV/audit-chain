package io.github.mustafakemalv.auditchain.store;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.mustafakemalv.auditchain.core.AuditRecord;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

class InMemoryAuditStoreTest {

    private static ChainedRecord chained(long sequence, String previousHash, String hash) {
        AuditRecord record = new AuditRecord(sequence, Instant.EPOCH, "actor", "action", null, null, Map.of());
        return new ChainedRecord(record, previousHash, hash);
    }

    @Test
    void lastIsEmptyWhenNoRecords() {
        assertThat(new InMemoryAuditStore().last()).isEmpty();
    }

    @Test
    void appendMakesRecordTheHead() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        ChainedRecord first = chained(0, "gen", "h0");
        ChainedRecord second = chained(1, "h0", "h1");

        store.append(first);
        store.append(second);

        assertThat(store.last()).contains(second);
        assertThat(store.count()).isEqualTo(2);
    }

    @Test
    void findAllReturnsRecordsInAppendOrder() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        ChainedRecord first = chained(0, "gen", "h0");
        ChainedRecord second = chained(1, "h0", "h1");
        store.append(first);
        store.append(second);

        assertThat(store.findAll()).containsExactly(first, second);
    }

    @Test
    void findAllReturnsACopy() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        store.append(chained(0, "gen", "h0"));

        store.findAll().clear();

        assertThat(store.count()).isEqualTo(1);
    }
}
