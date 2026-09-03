package io.github.mustafakemalv.auditchain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.mustafakemalv.auditchain.core.AuditEvent;
import io.github.mustafakemalv.auditchain.core.CanonicalEncoder;
import io.github.mustafakemalv.auditchain.core.ChainHead;
import io.github.mustafakemalv.auditchain.core.AuditRecord;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import io.github.mustafakemalv.auditchain.core.Checkpoint;
import io.github.mustafakemalv.auditchain.core.FailureReason;
import io.github.mustafakemalv.auditchain.core.VerificationResult;
import io.github.mustafakemalv.auditchain.store.AuditStore;
import io.github.mustafakemalv.auditchain.store.InMemoryAuditStore;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class AuditChainTest {

    private static final byte[] KEY = "an-audit-hmac-key".getBytes(StandardCharsets.UTF_8);
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-08-19T10:00:00Z"), ZoneOffset.UTC);

    private static AuditChain chainOver(AuditStore store) {
        return new AuditChain(KEY, store, AuditChain.DEFAULT_CHAIN_ID, CLOCK);
    }

    private static InMemoryAuditStore storeWithThreeRecords() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        AuditChain chain = chainOver(store);
        chain.append(AuditEvent.of("alice", "login", "user", "1"));
        chain.append(new AuditEvent("bob", "delete", "doc", "2", Map.of("reason", "cleanup")));
        chain.append(AuditEvent.of("carol", "update", "doc", "3"));
        return store;
    }

    @Test
    void emptyChainIsValid() {
        assertThat(chainOver(new InMemoryAuditStore()).verify().valid()).isTrue();
    }

    @Test
    void genesisRecordLinksToGenesisHash() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        ChainedRecord first = chainOver(store).append(AuditEvent.of("alice", "login"));
        assertThat(first.record().sequence()).isZero();
        assertThat(first.previousHash()).isEqualTo(AuditChain.GENESIS_PREVIOUS_HASH);
    }

    @Test
    void eachRecordLinksToThePreviousHash() {
        List<ChainedRecord> records = storeWithThreeRecords().findAll();
        assertThat(records.get(1).previousHash()).isEqualTo(records.get(0).hash());
        assertThat(records.get(2).previousHash()).isEqualTo(records.get(1).hash());
        assertThat(records.get(2).record().sequence()).isEqualTo(2L);
    }

    @Test
    void intactChainVerifiesAsValid() {
        VerificationResult result = chainOver(storeWithThreeRecords()).verify();
        assertThat(result.valid()).isTrue();
        assertThat(result.reason()).isEqualTo(FailureReason.NONE);
        assertThat(result.brokenSequence()).isEqualTo(-1L);
    }

    @Test
    void tamperedFieldIsDetectedAsHashMismatch() {
        List<ChainedRecord> good = storeWithThreeRecords().findAll();
        ChainedRecord original = good.get(1);
        AuditRecord altered = new AuditRecord(
                original.record().sequence(), original.record().timestamp(),
                "attacker", original.record().action(), original.record().resourceType(),
                original.record().resourceId(), original.record().details());
        // keep the old hash: without the key the attacker cannot forge a matching one
        ChainedRecord tampered = new ChainedRecord(altered, original.previousHash(), original.hash());

        InMemoryAuditStore store = new InMemoryAuditStore();
        store.append(good.get(0));
        store.append(tampered);
        store.append(good.get(2));

        VerificationResult result = chainOver(store).verify();
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.HASH_MISMATCH);
        assertThat(result.brokenSequence()).isEqualTo(1L);
    }

    @Test
    void brokenPreviousHashIsDetectedAsBrokenLink() {
        List<ChainedRecord> good = storeWithThreeRecords().findAll();
        ChainedRecord original = good.get(2);
        ChainedRecord broken = new ChainedRecord(original.record(), "0".repeat(64), original.hash());

        InMemoryAuditStore store = new InMemoryAuditStore();
        store.append(good.get(0));
        store.append(good.get(1));
        store.append(broken);

        VerificationResult result = chainOver(store).verify();
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.BROKEN_LINK);
        assertThat(result.brokenSequence()).isEqualTo(2L);
    }

    @Test
    void deletedRecordIsDetectedAsSequenceGap() {
        List<ChainedRecord> good = storeWithThreeRecords().findAll();
        InMemoryAuditStore store = new InMemoryAuditStore();
        store.append(good.get(0));
        store.append(good.get(2)); // sequence 2 where 1 is expected

        VerificationResult result = chainOver(store).verify();
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.SEQUENCE_GAP);
        assertThat(result.brokenSequence()).isEqualTo(2L);
    }

    @Test
    void reorderedRecordsAreDetected() {
        List<ChainedRecord> good = storeWithThreeRecords().findAll();
        // Reordering has to be staged through a store with no integrity checks: the real stores
        // refuse a sequence that does not move forward, so an attacker cannot reorder the log
        // through them. In production the same tampering happens below the store, straight against
        // the database, which is what this stand-in represents.
        TamperedStore store = new TamperedStore();
        store.append(good.get(0));
        store.append(good.get(2));
        store.append(good.get(1));

        VerificationResult result = chainOver(store).verify();
        assertThat(result.valid()).isFalse();
        // the record now in position 1 has sequence 2, but sequence 1 is expected
        assertThat(result.brokenSequence()).isEqualTo(2L);
    }

    /**
     * A store that accepts whatever it is handed, standing in for someone writing directly to the
     * database. Used to stage tampering that the real stores would refuse at the front door.
     */
    private static final class TamperedStore implements AuditStore {

        private final List<ChainedRecord> records = new ArrayList<>();
        private final long highWaterMark;

        TamperedStore() {
            this(0L);
        }

        /** Stands in for a chain whose head row still remembers a length the rows no longer reach. */
        TamperedStore(long highWaterMark) {
            this.highWaterMark = highWaterMark;
        }

        @Override
        public ChainHead head(String genesisHash) {
            long mark = Math.max(highWaterMark, records.size());
            if (records.isEmpty()) {
                return new ChainHead(-1L, genesisHash, mark);
            }
            ChainedRecord last = records.get(records.size() - 1);
            return new ChainHead(last.record().sequence(), last.hash(), mark);
        }

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

    @Test
    void rejectsEmptyKey() {
        assertThatThrownBy(() -> new AuditChain(new byte[0], new InMemoryAuditStore()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void headIsEmptyForAnEmptyChain() {
        assertThat(chainOver(new InMemoryAuditStore()).head()).isEmpty();
    }

    @Test
    void headReturnsTheLastCheckpoint() {
        InMemoryAuditStore store = storeWithThreeRecords();
        Checkpoint head = chainOver(store).head().orElseThrow();
        assertThat(head.sequence()).isEqualTo(2L);
        assertThat(head.hash()).isEqualTo(store.findAll().get(2).hash());
    }

    @Test
    void verifyAgainstMatchingCheckpointIsValid() {
        AuditChain chain = chainOver(storeWithThreeRecords());
        Checkpoint anchor = chain.head().orElseThrow();
        assertThat(chain.verifyAgainstCheckpoint(anchor).valid()).isTrue();
    }

    @Test
    void verifyAgainstCheckpointDetectsAKeyedRewrite() {
        // anchor the original chain's head somewhere external
        Checkpoint anchor = chainOver(storeWithThreeRecords()).head().orElseThrow();

        // attacker rebuilds a DIFFERENT but internally-consistent chain with the SAME key
        InMemoryAuditStore rewritten = new InMemoryAuditStore();
        AuditChain rewrittenChain = chainOver(rewritten);
        rewrittenChain.append(AuditEvent.of("alice", "login", "user", "1"));
        rewrittenChain.append(new AuditEvent("bob", "delete", "doc", "2", Map.of("reason", "cleanup")));
        rewrittenChain.append(AuditEvent.of("attacker", "update", "doc", "3")); // tampered content

        // it verifies internally...
        assertThat(rewrittenChain.verify().valid()).isTrue();
        // ...but not against the externally anchored checkpoint
        VerificationResult result = rewrittenChain.verifyAgainstCheckpoint(anchor);
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.CHECKPOINT_MISMATCH);
        assertThat(result.brokenSequence()).isEqualTo(2L);
    }

    @Test
    void verifyAgainstCheckpointReportsTheInternalFailureFirst() {
        // an internally broken chain reports its own failure, before looking at the checkpoint
        List<ChainedRecord> good = storeWithThreeRecords().findAll();
        InMemoryAuditStore tampered = new InMemoryAuditStore();
        tampered.append(good.get(0));
        tampered.append(good.get(2)); // sequence 1 removed
        Checkpoint anchor = new Checkpoint(2L, good.get(2).hash());

        assertThat(chainOver(tampered).verifyAgainstCheckpoint(anchor).reason())
                .isEqualTo(FailureReason.SEQUENCE_GAP);
    }

    @Test
    void verifyAgainstCheckpointDetectsAChainShorterThanTheAnchor() {
        // The chain is internally valid but no longer reaches the anchored sequence, which is what
        // deleting everything above the anchor looks like. Reported as TRUNCATED rather than a
        // checkpoint mismatch, because the anchor did not disagree with a record: the record is gone.
        AuditChain chain = chainOver(storeWithThreeRecords());
        Checkpoint anchor = new Checkpoint(99L, "0".repeat(64));

        VerificationResult result = chain.verifyAgainstCheckpoint(anchor);
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.TRUNCATED);
        assertThat(result.brokenSequence()).isEqualTo(99L);
    }

    @Test
    void checkpointRejectsNullHash() {
        assertThatThrownBy(() -> new Checkpoint(0L, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void recordsCannotBeMovedIntoAnotherChainSealedWithTheSameKey() {
        // One key covering several logs is the natural multi-tenant setup. Without a chain identity
        // in the hash, a genuine, correctly signed history from one tenant verified perfectly inside
        // another tenant's log, so an incriminating trail could simply be replaced with someone
        // else's.
        InMemoryAuditStore tenantA = new InMemoryAuditStore();
        AuditChain chainA = new AuditChain(KEY, tenantA, "tenant-a", CLOCK);
        chainA.append(AuditEvent.of("alice", "invoice.approve"));
        chainA.append(AuditEvent.of("alice", "invoice.approve"));
        assertThat(chainA.verify().valid()).isTrue();

        TamperedStore tenantB = new TamperedStore();
        AuditChain chainB = new AuditChain(KEY, tenantB, "tenant-b", CLOCK);
        tenantA.findAll().forEach(tenantB::append);

        VerificationResult result = chainB.verify();
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.HASH_MISMATCH);
        assertThat(result.brokenSequence()).isZero();
    }

    @Test
    void theSameEventUnderTwoChainIdsProducesDifferentHashes() {
        InMemoryAuditStore first = new InMemoryAuditStore();
        InMemoryAuditStore second = new InMemoryAuditStore();
        ChainedRecord a = new AuditChain(KEY, first, "chain-one", CLOCK)
                .append(AuditEvent.of("alice", "login"));
        ChainedRecord b = new AuditChain(KEY, second, "chain-two", CLOCK)
                .append(AuditEvent.of("alice", "login"));

        assertThat(a.record()).isEqualTo(b.record());
        assertThat(a.hash()).isNotEqualTo(b.hash());
    }

    @Test
    void rejectsAnEmptyChainId() {
        assertThatThrownBy(() -> new AuditChain(KEY, new InMemoryAuditStore(), ""))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AuditChain(KEY, new InMemoryAuditStore(), null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void appendedRecordsCarryTheFormatVersionTheyWereSealedUnder() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        ChainedRecord record = chainOver(store).append(AuditEvent.of("alice", "login"));

        assertThat(record.formatVersion()).isEqualTo(CanonicalEncoder.CURRENT_FORMAT_VERSION);
    }

    @Test
    void aRecordClaimingAnUnknownFormatVersionIsReportedAsUnreadable() {
        // A row whose version this build cannot write must not be hashed under a guessed layout,
        // which would report a mismatch and read as tampering. It must also not throw: verify() has
        // to answer for any content the table happens to hold.
        List<ChainedRecord> good = storeWithThreeRecords().findAll();
        ChainedRecord first = good.get(0);
        TamperedStore store = new TamperedStore();
        store.append(new ChainedRecord(first.record(), first.previousHash(), first.hash(), 99));

        VerificationResult result = chainOver(store).verify();
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.UNREADABLE_RECORD);
        assertThat(result.brokenSequence()).isZero();
    }

    @Test
    void deletingTheNewestRecordsIsDetected() {
        // The whole point of the high-water mark. What remains is a perfectly valid shorter chain,
        // so the hash links alone say "intact"; only the remembered length reveals the deletion.
        InMemoryAuditStore store = new InMemoryAuditStore();
        AuditChain chain = chainOver(store);
        for (int i = 0; i < 5; i++) {
            chain.append(AuditEvent.of("alice", "act." + i));
        }
        assertThat(chain.verify().valid()).isTrue();

        // an attacker deletes the three newest rows, straight against the database
        TamperedStore truncated = new TamperedStore(store.head(AuditChain.GENESIS_PREVIOUS_HASH).recordCount());
        store.findRange(0L, 2).forEach(truncated::append);

        VerificationResult result = chainOver(truncated).verify();
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.TRUNCATED);
        assertThat(result.brokenSequence()).isEqualTo(2L);
    }

    @Test
    void deletingTheEntireLogIsDetected() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        AuditChain chain = chainOver(store);
        for (int i = 0; i < 5; i++) {
            chain.append(AuditEvent.of("alice", "act." + i));
        }

        TamperedStore wiped = new TamperedStore(store.head(AuditChain.GENESIS_PREVIOUS_HASH).recordCount());

        VerificationResult result = chainOver(wiped).verify();
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.TRUNCATED);
        assertThat(result.brokenSequence()).isZero();
    }

    @Test
    void anIntactChainIsNotReportedAsTruncated() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        AuditChain chain = chainOver(store);
        for (int i = 0; i < 5; i++) {
            chain.append(AuditEvent.of("alice", "act." + i));
        }

        assertThat(chain.verify().valid()).isTrue();
        assertThat(chain.verify().reason()).isEqualTo(FailureReason.NONE);
    }
}
