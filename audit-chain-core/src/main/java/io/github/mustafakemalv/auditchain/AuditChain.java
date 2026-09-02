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
 * {@code hash(n) = HMAC-SHA256(key, domainTag ‖ chainId ‖ canonicalBytes(record) ‖ previousHash)},
 * with every part length-prefixed, and the genesis record links to {@link #GENESIS_PREVIOUS_HASH}.
 * {@link #verify()} recomputes every hash and returns the first record that breaks the chain.
 *
 * <p>Scope: this detects tampering by anyone who does not hold the HMAC key. It cannot stop an
 * attacker who holds the key or can rewrite the whole log consistently.
 *
 * <p><b>Chain identity.</b> The {@code chainId} is bound into every hash, so a record is only valid
 * inside the chain it was written for. Without it, any chain sealed with the same key would accept
 * another chain's records wholesale: an attacker with read access to one audit table and write
 * access to another could replace a damning history with a genuine, correctly signed one. Give each
 * chain its own id whenever one key covers more than one log.
 *
 * <p><b>Concurrency.</b> {@link #append(AuditEvent)} is synchronized, which serializes appends made
 * through this instance. That is not the whole story once appends run inside database transactions,
 * where the insert stays invisible until commit; see the store's documentation. Note also that a
 * hash chain is serial by nature, because a record cannot be sealed until the one before it is
 * committed. Throughput therefore scales by running several chains, each with its own id and table,
 * rather than by making one chain faster.
 */
public class AuditChain {

    /** The previous-hash value the first (genesis) record links to: 32 zero bytes as hex. */
    public static final String GENESIS_PREVIOUS_HASH = "0".repeat(64);

    /** The chain id used when none is given. */
    public static final String DEFAULT_CHAIN_ID = "default";

    /**
     * Separates this construction from any other use of the same key. Bump the suffix if the shape
     * of the hashed message itself ever changes, as opposed to the record encoding, which carries
     * its own version.
     */
    private static final String DOMAIN_TAG = "audit-chain/v1";

    private final byte[] key;
    private final AuditStore store;
    private final Clock clock;
    private final String chainId;

    /**
     * Creates a chain with the {@link #DEFAULT_CHAIN_ID}.
     *
     * @param key the HMAC key
     * @param store where records are kept
     */
    public AuditChain(byte[] key, AuditStore store) {
        this(key, store, DEFAULT_CHAIN_ID);
    }

    /**
     * Creates a chain with an explicit identity.
     *
     * @param key the HMAC key
     * @param store where records are kept
     * @param chainId identifies this chain, and is bound into every hash so records cannot be moved
     *     between chains that share a key
     */
    public AuditChain(byte[] key, AuditStore store, String chainId) {
        this(key, store, chainId, Clock.systemUTC());
    }

    AuditChain(byte[] key, AuditStore store, String chainId, Clock clock) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("key must not be empty");
        }
        if (store == null) {
            throw new IllegalArgumentException("store is required");
        }
        if (chainId == null || chainId.isEmpty()) {
            throw new IllegalArgumentException("chainId must not be empty");
        }
        if (clock == null) {
            throw new IllegalArgumentException("clock is required");
        }
        this.key = key.clone();
        this.store = store;
        this.chainId = chainId;
        this.clock = clock;
    }

    /** @return the identity bound into this chain's hashes */
    public String chainId() {
        return chainId;
    }

    /**
     * Appends {@code event} as the new head of the chain and returns the stored record.
     *
     * @param event what happened
     * @return the record as it was stored
     */
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
        int formatVersion = CanonicalEncoder.CURRENT_FORMAT_VERSION;
        String hash = computeHash(record, previousHash, formatVersion);
        ChainedRecord chained = new ChainedRecord(record, previousHash, hash, formatVersion);
        store.append(chained);
        return chained;
    }

    /**
     * Walks the chain from the start, recomputing each hash, and returns the first record that
     * breaks it, or {@link VerificationResult#intact()} if the whole chain is intact.
     *
     * @return where the chain first breaks, or an intact result
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
            String recomputed = computeHash(record, chained.previousHash(), chained.formatVersion());
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

    /**
     * The checkpoint (sequence + hash) of the current head, or empty if the chain has no records.
     *
     * @return the head checkpoint, or empty
     */
    public Optional<Checkpoint> head() {
        return store.last().map(record -> new Checkpoint(record.record().sequence(), record.hash()));
    }

    /**
     * Verifies the chain internally and then against an externally anchored {@code checkpoint}. This
     * can catch a rewrite that {@link #verify()} cannot (for example one made with a stolen key),
     * because the rewritten hash no longer matches the checkpoint that was anchored elsewhere.
     *
     * @param checkpoint a head checkpoint recorded earlier, ideally somewhere the chain's owner
     *     cannot quietly change
     * @return an intact result, or where the chain disagrees with the checkpoint
     */
    public VerificationResult verifyAgainstCheckpoint(Checkpoint checkpoint) {
        if (checkpoint == null) {
            throw new IllegalArgumentException("checkpoint is required");
        }
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

    private String computeHash(AuditRecord record, String previousHash, int formatVersion) {
        byte[] canonical = CanonicalEncoder.encode(record, formatVersion);
        return Hmac.hex(Hmac.sha256(key, chainMessage(canonical, previousHash)));
    }

    /**
     * Builds the message that gets hashed by length-prefixing every part: a domain tag, the chain
     * id, the record bytes and the previous hash. Prefixing makes each boundary explicit, so no
     * combination of parts can be re-split into a different combination with the same bytes. This
     * holds without relying on any part having a fixed width.
     */
    private byte[] chainMessage(byte[] canonical, String previousHash) {
        byte[] domainBytes = DOMAIN_TAG.getBytes(StandardCharsets.UTF_8);
        byte[] chainIdBytes = chainId.getBytes(StandardCharsets.UTF_8);
        byte[] previousHashBytes = previousHash.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(
                domainBytes.length + chainIdBytes.length + canonical.length + previousHashBytes.length + 16);
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.writeInt(domainBytes.length);
            out.write(domainBytes);
            out.writeInt(chainIdBytes.length);
            out.write(chainIdBytes);
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
