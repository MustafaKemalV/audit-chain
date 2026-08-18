package io.github.mustafakemalv.auditchain;

import io.github.mustafakemalv.auditchain.core.AuditEvent;
import io.github.mustafakemalv.auditchain.core.AuditRecord;
import io.github.mustafakemalv.auditchain.core.CanonicalEncoder;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import io.github.mustafakemalv.auditchain.core.FailureReason;
import io.github.mustafakemalv.auditchain.core.Hmac;
import io.github.mustafakemalv.auditchain.core.VerificationResult;
import io.github.mustafakemalv.auditchain.store.AuditStore;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Appends tamper-evident records to an {@link AuditStore} and verifies the chain. Each record is
 * hash-chained to the previous one:
 * {@code hash(n) = HMAC-SHA256(key, canonicalBytes(record) || previousHash)}, and the genesis record
 * links to {@link #GENESIS_PREVIOUS_HASH}. {@link #verify()} recomputes every hash and returns the
 * first record that breaks the chain.
 *
 * <p>Scope: this detects tampering by anyone who does not hold the HMAC key. It cannot stop an
 * attacker who holds the key or can rewrite the whole log consistently. {@link #append(AuditEvent)}
 * is synchronized, which is correct for a single JVM; a distributed deployment needs sequence
 * coordination at the storage layer.
 */
public class AuditChain {

    /** The previous-hash value the first (genesis) record links to: 32 zero bytes as hex. */
    public static final String GENESIS_PREVIOUS_HASH = "0".repeat(64);

    private final byte[] key;
    private final AuditStore store;
    private final Clock clock;

    public AuditChain(byte[] key, AuditStore store) {
        this(key, store, Clock.systemUTC());
    }

    AuditChain(byte[] key, AuditStore store, Clock clock) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("key must not be empty");
        }
        if (store == null) {
            throw new IllegalArgumentException("store is required");
        }
        if (clock == null) {
            throw new IllegalArgumentException("clock is required");
        }
        this.key = key.clone();
        this.store = store;
        this.clock = clock;
    }

    /** Appends {@code event} as the new head of the chain and returns the stored record. */
    public synchronized ChainedRecord append(AuditEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("event is required");
        }
        ChainedRecord previous = store.last().orElse(null);
        long sequence = previous == null ? 0L : previous.record().sequence() + 1;
        String previousHash = previous == null ? GENESIS_PREVIOUS_HASH : previous.hash();
        Instant timestamp = clock.instant().truncatedTo(ChronoUnit.MILLIS);
        AuditRecord record = new AuditRecord(sequence, timestamp, event.actor(), event.action(),
                event.resourceType(), event.resourceId(), event.details());
        String hash = computeHash(record, previousHash);
        ChainedRecord chained = new ChainedRecord(record, previousHash, hash);
        store.append(chained);
        return chained;
    }

    /**
     * Walks the chain from the start, recomputing each hash, and returns the first record that
     * breaks it, or {@link VerificationResult#valid()} if the whole chain is intact.
     */
    public VerificationResult verify() {
        String expectedPreviousHash = GENESIS_PREVIOUS_HASH;
        long expectedSequence = 0L;
        for (ChainedRecord chained : store.findAll()) {
            AuditRecord record = chained.record();
            if (record.sequence() != expectedSequence) {
                return VerificationResult.broken(record.sequence(), FailureReason.SEQUENCE_GAP);
            }
            if (!chained.previousHash().equals(expectedPreviousHash)) {
                return VerificationResult.broken(record.sequence(), FailureReason.BROKEN_LINK);
            }
            String recomputed = computeHash(record, chained.previousHash());
            if (!Hmac.constantTimeEquals(
                    recomputed.getBytes(StandardCharsets.UTF_8),
                    chained.hash().getBytes(StandardCharsets.UTF_8))) {
                return VerificationResult.broken(record.sequence(), FailureReason.HASH_MISMATCH);
            }
            expectedPreviousHash = chained.hash();
            expectedSequence = record.sequence() + 1;
        }
        return VerificationResult.intact();
    }

    private String computeHash(AuditRecord record, String previousHash) {
        byte[] canonical = CanonicalEncoder.encode(record);
        byte[] previousHashBytes = previousHash.getBytes(StandardCharsets.UTF_8);
        byte[] message = new byte[canonical.length + previousHashBytes.length];
        System.arraycopy(canonical, 0, message, 0, canonical.length);
        System.arraycopy(previousHashBytes, 0, message, canonical.length, previousHashBytes.length);
        return Hmac.hex(Hmac.sha256(key, message));
    }
}
