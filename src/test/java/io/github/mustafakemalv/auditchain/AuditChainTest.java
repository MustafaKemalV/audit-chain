package io.github.mustafakemalv.auditchain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.mustafakemalv.auditchain.core.AuditEvent;
import io.github.mustafakemalv.auditchain.core.AuditRecord;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import io.github.mustafakemalv.auditchain.core.Checkpoint;
import io.github.mustafakemalv.auditchain.core.FailureReason;
import io.github.mustafakemalv.auditchain.core.VerificationResult;
import io.github.mustafakemalv.auditchain.store.InMemoryAuditStore;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AuditChainTest {

    private static final byte[] KEY = "an-audit-hmac-key".getBytes(StandardCharsets.UTF_8);
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-08-19T10:00:00Z"), ZoneOffset.UTC);

    private static AuditChain chainOver(InMemoryAuditStore store) {
        return new AuditChain(KEY, store, CLOCK);
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
        InMemoryAuditStore store = new InMemoryAuditStore();
        store.append(good.get(0));
        store.append(good.get(2));
        store.append(good.get(1));

        VerificationResult result = chainOver(store).verify();
        assertThat(result.valid()).isFalse();
        // the record now in position 1 has sequence 2, but sequence 1 is expected
        assertThat(result.brokenSequence()).isEqualTo(2L);
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
    void verifyAgainstCheckpointDetectsAMissingAnchoredRecord() {
        // the chain is internally valid, but the anchored sequence is not in it
        AuditChain chain = chainOver(storeWithThreeRecords());
        Checkpoint anchor = new Checkpoint(99L, "0".repeat(64));

        VerificationResult result = chain.verifyAgainstCheckpoint(anchor);
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.CHECKPOINT_MISMATCH);
        assertThat(result.brokenSequence()).isEqualTo(99L);
    }

    @Test
    void checkpointRejectsNullHash() {
        assertThatThrownBy(() -> new Checkpoint(0L, null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
