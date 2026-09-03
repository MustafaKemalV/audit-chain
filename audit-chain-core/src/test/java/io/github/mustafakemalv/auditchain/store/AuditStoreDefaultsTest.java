package io.github.mustafakemalv.auditchain.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.mustafakemalv.auditchain.AuditChain;
import io.github.mustafakemalv.auditchain.core.AuditEvent;
import io.github.mustafakemalv.auditchain.core.AuditRecord;
import io.github.mustafakemalv.auditchain.core.ChainHead;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Exercises the SPI through a store that implements only the four required methods, which is what a
 * third party writing their own backend actually starts from. The defaults are the compatibility
 * promise: adding {@code findRange}, {@code head}, {@code lockHead} and {@code appendSealed} was
 * only safe because a store written before they existed still works.
 */
class AuditStoreDefaultsTest {

    private static final byte[] KEY = "an-audit-hmac-key".getBytes(StandardCharsets.UTF_8);

    /** The bare minimum an implementer has to write. Everything else comes from the interface. */
    private static final class MinimalStore implements AuditStore {

        private final List<ChainedRecord> records = new ArrayList<>();

        @Override
        public void append(ChainedRecord record) {
            records.add(record);
        }

        @Override
        public Optional<ChainedRecord> last() {
            return records.isEmpty() ? Optional.empty() : Optional.of(records.get(records.size() - 1));
        }

        @Override
        public List<ChainedRecord> findAll() {
            return new ArrayList<>(records);
        }

        @Override
        public long count() {
            return records.size();
        }
    }

    private static ChainedRecord chained(long sequence) {
        AuditRecord record = new AuditRecord(sequence, Instant.EPOCH, "actor", "action", null, null, Map.of());
        return new ChainedRecord(record, "prev-" + sequence, "hash-" + sequence);
    }

    @Test
    void aStoreWithOnlyTheRequiredMethodsWorksAsAChain() {
        MinimalStore store = new MinimalStore();
        AuditChain chain = new AuditChain(KEY, store);

        chain.append(AuditEvent.of("alice", "login"));
        chain.append(AuditEvent.of("bob", "logout"));

        assertThat(chain.verify().valid()).isTrue();
        assertThat(store.count()).isEqualTo(2L);
    }

    @Test
    void findRangeDefaultsToASliceOfFindAll() {
        MinimalStore store = new MinimalStore();
        for (long i = 0; i < 6; i++) {
            store.append(chained(i));
        }

        assertThat(store.findRange(2L, 3).stream().map(r -> r.record().sequence()).toList())
                .containsExactly(2L, 3L, 4L);
        assertThat(store.findRange(5L, 10)).hasSize(1);
        assertThat(store.findRange(6L, 10)).isEmpty();
        assertThatThrownBy(() -> store.findRange(0L, 0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> store.findRange(0L, -1)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void headDefaultsToTheLastRecordAndTheCurrentCount() {
        MinimalStore store = new MinimalStore();
        assertThat(store.head(AuditChain.GENESIS_PREVIOUS_HASH))
                .isEqualTo(ChainHead.empty(AuditChain.GENESIS_PREVIOUS_HASH));

        store.append(chained(0));
        store.append(chained(1));

        ChainHead head = store.head(AuditChain.GENESIS_PREVIOUS_HASH);
        assertThat(head.lastSequence()).isEqualTo(1L);
        assertThat(head.lastHash()).isEqualTo("hash-1");
        assertThat(head.recordCount()).isEqualTo(2L);
        assertThat(head.nextSequence()).isEqualTo(2L);
        assertThat(head.isEmpty()).isFalse();
    }

    @Test
    void theDefaultHeadCannotSeeATruncatedChain() {
        // Worth pinning as a known limit rather than leaving it to be discovered. A count taken from
        // the rows that remain always agrees with those rows, so a store without a durable
        // high-water mark cannot tell that records were deleted from the end. The JDBC store keeps
        // one; a minimal store does not.
        MinimalStore store = new MinimalStore();
        for (long i = 0; i < 4; i++) {
            store.append(chained(i));
        }
        store.records.remove(3);

        assertThat(store.head(AuditChain.GENESIS_PREVIOUS_HASH).recordCount())
                .as("the count follows the rows, so the deletion is invisible here")
                .isEqualTo(3L);
    }

    @Test
    void lockHeadDefaultsToPlainReading() {
        MinimalStore store = new MinimalStore();
        store.append(chained(0));

        assertThat(store.lockHead(AuditChain.GENESIS_PREVIOUS_HASH))
                .isEqualTo(store.head(AuditChain.GENESIS_PREVIOUS_HASH));
    }

    @Test
    void appendSealedDefaultsToReadingTheTipThenAppending() {
        MinimalStore store = new MinimalStore();
        store.append(chained(0));

        ChainedRecord sealed = store.appendSealed(AuditChain.GENESIS_PREVIOUS_HASH,
                head -> chained(head.nextSequence()));

        assertThat(sealed.record().sequence()).isEqualTo(1L);
        assertThat(store.count()).isEqualTo(2L);
        assertThat(store.last()).contains(sealed);
    }
}
