package io.github.mustafakemalv.auditchain;

import io.github.mustafakemalv.auditchain.core.AuditEvent;
import io.github.mustafakemalv.auditchain.core.AuditRecord;
import io.github.mustafakemalv.auditchain.core.CanonicalEncoder;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import io.github.mustafakemalv.auditchain.core.Checkpoint;
import io.github.mustafakemalv.auditchain.core.FailureReason;
import io.github.mustafakemalv.auditchain.core.Hmac;
import io.github.mustafakemalv.auditchain.core.VerificationResult;
import io.github.mustafakemalv.auditchain.store.AuditStore;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

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
        Instant timestamp = clock.instant(); // AuditRecord truncates to millis
        AuditRecord record = new AuditRecord(sequence, timestamp, event.actor(), event.action(),
                event.resourceType(), event.resourceId(), event.details());
        String hash = computeHash(record, previousHash);
        ChainedRecord chained = new ChainedRecord(record, previousHash, hash);
        store.append(chained);
        return chained;
    }

    /**
     * Walks the chain from the start, recomputing each hash, and returns the first record that
     * breaks it, or {@link VerificationResult#intact()} if the whole chain is intact.
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

    /** The checkpoint (sequence + hash) of the current head, or empty if the chain has no records. */
    public Optional<Checkpoint> head() {
        return store.last().map(record -> new Checkpoint(record.record().sequence(), record.hash()));
    }

    /**
     * Verifies the chain internally and then against an externally anchored {@code checkpoint}. This
     * can catch a rewrite that {@link #verify()} cannot (for example one made with a stolen key),
     * because the rewritten hash no longer matches the checkpoint that was anchored elsewhere.
     */
    public VerificationResult verifyAgainstCheckpoint(Checkpoint checkpoint) {
        VerificationResult internal = verify();
        if (!internal.valid()) {
            return internal;
        }
        for (ChainedRecord chained : store.findAll()) {
            if (chained.record().sequence() == checkpoint.sequence()) {
                boolean matches = Hmac.constantTimeEquals(
                        chained.hash().getBytes(StandardCharsets.UTF_8),
                        checkpoint.hash().getBytes(StandardCharsets.UTF_8));
                return matches
                        ? VerificationResult.intact()
                        : VerificationResult.broken(checkpoint.sequence(), FailureReason.CHECKPOINT_MISMATCH);
            }
        }
        return VerificationResult.broken(checkpoint.sequence(), FailureReason.CHECKPOINT_MISMATCH);
    }

    private String computeHash(AuditRecord record, String previousHash) {
        byte[] canonical = CanonicalEncoder.encode(record);
        return Hmac.hex(Hmac.sha256(key, chainMessage(canonical, previousHash)));
    }

    /**
     * Builds the message that gets hashed by length-prefixing both parts. Prefixing makes the
     * boundary between the record bytes and the previous hash explicit, so no (record, previousHash)
     * pair can ever be re-split into a different pair with the same bytes. This holds without relying
     * on the previous hash always being a fixed width.
     */
    private byte[] chainMessage(byte[] canonical, String previousHash) {
        byte[] previousHashBytes = previousHash.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream buffer =
                new ByteArrayOutputStream(canonical.length + previousHashBytes.length + 8);
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.writeInt(canonical.length);
            out.write(canonical);
            out.writeInt(previousHashBytes.length);
            out.write(previousHashBytes);
        } catch (IOException e) {
            throw new IllegalStateException("Encoding to an in-memory buffer cannot fail", e);
        }
        return buffer.toByteArray();
    }
}
