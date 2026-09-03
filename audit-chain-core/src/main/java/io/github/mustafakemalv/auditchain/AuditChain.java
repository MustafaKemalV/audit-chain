package io.github.mustafakemalv.auditchain;

import io.github.mustafakemalv.auditchain.core.AuditEvent;
import io.github.mustafakemalv.auditchain.core.AuditRecord;
import io.github.mustafakemalv.auditchain.core.CanonicalEncoder;
import io.github.mustafakemalv.auditchain.core.ChainHead;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import io.github.mustafakemalv.auditchain.core.Checkpoint;
import io.github.mustafakemalv.auditchain.core.FailureReason;
import io.github.mustafakemalv.auditchain.core.Hmac;
import io.github.mustafakemalv.auditchain.core.VerificationResult;
import io.github.mustafakemalv.auditchain.store.AuditStore;
import io.github.mustafakemalv.auditchain.store.MalformedRecordException;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
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
 * <p><b>Concurrency.</b> Appends are serialized by the store, not here. This class holds no lock of
 * its own: it used to, and combining a lock released on return with a database row lock held until
 * commit produced a deadlock between two appends in one transaction, which the JVM's own detector
 * cannot even see because half the cycle lives in the database. The store is the only place that can
 * serialize correctly, because only it knows when the write is durable.
 *
 * <p>A hash chain is serial by nature: a record cannot be sealed until the one before it is settled.
 * Throughput therefore scales by running several chains, each with its own id and table, rather than
 * by making one chain faster.
 */
public final class AuditChain {

    /**
     * The previous-hash value the first (genesis) record links to: 32 zero bytes as hex.
     *
     * @see ChainHead#GENESIS_HASH
     */
    public static final String GENESIS_PREVIOUS_HASH = ChainHead.GENESIS_HASH;

    /** The chain id used when none is given. */
    public static final String DEFAULT_CHAIN_ID = "default";

    /**
     * Separates this construction from any other use of the same key. Bump the suffix if the shape
     * of the hashed message itself ever changes, as opposed to the record encoding, which carries
     * its own version.
     */
    private static final String DOMAIN_TAG = "audit-chain/v1";

    /**
     * How many records verification reads at a time. Verifying used to load the entire log at once,
     * which is a guaranteed out-of-memory failure on a chain that has been running for years.
     */
    private static final int VERIFY_PAGE_SIZE = 1000;

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
    public ChainedRecord append(AuditEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("event is required");
        }
        // Handing the whole step to the store keeps reading the tip and writing the record in one
        // unit of work. Doing it here as two calls would let two writers read the same tip and
        // compute the same sequence number, and one of their records would be lost.
        return store.appendSealed(head -> seal(head, event));
    }

    /** Builds the record that attaches to {@code head}. Called by the store, under its lock. */
    private ChainedRecord seal(ChainHead head, AuditEvent event) {
        long sequence = head.nextSequence();
        String previousHash = head.lastHash();
        Instant timestamp = clock.instant(); // AuditRecord truncates to millis
        AuditRecord record = new AuditRecord(sequence, timestamp, event.actor(), event.action(),
                event.resourceType(), event.resourceId(), event.details());
        int formatVersion = CanonicalEncoder.CURRENT_FORMAT_VERSION;
        String hash = computeHash(record, previousHash, formatVersion);
        return new ChainedRecord(record, previousHash, hash, formatVersion);
    }

    /**
     * Appends {@code event} in a transaction of its own, so it neither rolls back with the caller's
     * work nor can fail it.
     *
     * <p>Use this to record something whose fate is deliberately separate from the surrounding
     * operation: an attempt that was rolled back, or a read that has no transaction to share. It
     * gives up the guarantee that {@link #append(AuditEvent)} provides, so reach for it knowingly.
     *
     * @param event what happened
     * @return the record as it was stored
     */
    public ChainedRecord appendIndependently(AuditEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("event is required");
        }
        return store.appendSealedIndependently(head -> seal(head, event));
    }

    /**
     * Walks the chain from the start, recomputing each hash, and returns the first record that
     * breaks it, or {@link VerificationResult#intact()} if the whole chain is intact.
     *
     * @return where the chain first breaks, or an intact result
     */
    public VerificationResult verify() {
        ChainHead head;
        try {
            head = store.head();
        } catch (MalformedRecordException e) {
            // The stored tip itself will not read back. That is the same class of evidence as a
            // corrupt record, and reporting it beats throwing at a caller who asked a yes-or-no
            // question about the log's integrity.
            return VerificationResult.broken(0L, FailureReason.CHAIN_HEAD_MISMATCH);
        }
        String expectedPreviousHash = GENESIS_PREVIOUS_HASH;
        long expectedSequence = 0L;
        long seen = 0L;

        while (true) {
            List<ChainedRecord> page;
            try {
                page = store.findRange(expectedSequence, VERIFY_PAGE_SIZE);
            } catch (MalformedRecordException e) {
                // A row whose bytes cannot be read back is what tampering looks like, so it is
                // reported as a break rather than thrown at the caller. Verification has to stay
                // total: a monitoring job asking "is the log intact" must get an answer for any
                // content the table happens to hold.
                return locateUnreadableRecord(expectedSequence);
            }
            if (page.isEmpty()) {
                break;
            }
            for (ChainedRecord chained : page) {
                AuditRecord record = chained.record();
                if (record.sequence() != expectedSequence) {
                    return VerificationResult.broken(record.sequence(), FailureReason.SEQUENCE_GAP);
                }
                if (!chained.previousHash().equals(expectedPreviousHash)) {
                    return VerificationResult.broken(record.sequence(), FailureReason.BROKEN_LINK);
                }
                String recomputed;
                try {
                    recomputed = computeHash(record, chained.previousHash(), chained.formatVersion());
                } catch (IllegalArgumentException e) {
                    // A record claiming a format this build cannot write. Hashing it under a guessed
                    // layout would report a mismatch, which reads as tampering that did not happen.
                    return VerificationResult.broken(record.sequence(), FailureReason.UNREADABLE_RECORD);
                }
                if (!Hmac.constantTimeEquals(
                        recomputed.getBytes(StandardCharsets.UTF_8),
                        chained.hash().getBytes(StandardCharsets.UTF_8))) {
                    return VerificationResult.broken(record.sequence(), FailureReason.HASH_MISMATCH);
                }
                expectedPreviousHash = chained.hash();
                expectedSequence = record.sequence() + 1;
                seen++;
            }
        }

        // Everything above only proves that the records present form a valid chain, and a truncated
        // chain does exactly that. The stored tip is the only thing that remembers how long the
        // chain has been, so these two checks are what make deleting the newest records visible.
        //
        // The tip was read before the walk, deliberately: an append landing while we page can only
        // make the chain longer than the tip we hold, never shorter, so neither check can fire on a
        // chain that is merely growing.
        if (seen < head.recordCount()) {
            return VerificationResult.broken(seen, FailureReason.TRUNCATED);
        }
        if (head.isEmpty() && seen > 0) {
            // Records with no tip at all. Removing the tip row used to disable the truncation check
            // silently, so deleting it along with the records reported a clean chain; the two
            // sources contradicting each other is free to detect and says more than either alone.
            return VerificationResult.broken(0L, FailureReason.CHAIN_HEAD_MISMATCH);
        }
        return VerificationResult.intact();
    }

    /** Walks one page a record at a time to name the sequence whose stored bytes will not decode. */
    private VerificationResult locateUnreadableRecord(long fromSequence) {
        // Narrow the page by halving it rather than stepping through it. Reading one record at a
        // time cost a query per record, so corrupting a single cell near the end of a page bought a
        // thousandfold amplification of every scheduled verification: cheap for the attacker,
        // expensive forever after. Halving makes it about ten queries.
        long start = fromSequence;
        int span = VERIFY_PAGE_SIZE;
        while (span > 1) {
            int half = span / 2;
            List<ChainedRecord> firstHalf;
            try {
                firstHalf = store.findRange(start, half);
            } catch (MalformedRecordException e) {
                span = half;          // the bad record is in the half we just tried
                continue;
            }
            if (firstHalf.size() < half) {
                // The first half held every record there is, so nothing further to narrow into.
                break;
            }
            start = firstHalf.get(firstHalf.size() - 1).record().sequence() + 1;
            span -= half;             // it must be in the half we have not tried
        }
        return VerificationResult.broken(start, FailureReason.UNREADABLE_RECORD);
    }

    /**
     * The checkpoint (sequence + hash) of the current head, or empty if the chain has no records.
     *
     * @return the head checkpoint, or empty
     */
    public Optional<Checkpoint> head() {
        // From a real record, not from the stored tip. Anchoring what the tip claims would let
        // anyone who can write to it choose what gets anchored: set the tip back, let the anchoring
        // job export that, then delete everything above it, and both verifications pass. An anchor
        // is only worth what its source is worth.
        return store.last().map(record -> new Checkpoint(record.record().sequence(), record.hash()));
    }

    /**
     * Verifies the chain internally and then against an externally anchored {@code checkpoint}. This
     * can catch a rewrite that {@link #verify()} cannot (for example one made with a stolen key),
     * because the rewritten hash no longer matches the checkpoint that was anchored elsewhere. It
     * also rejects a chain that no longer reaches the anchored sequence, which is what deleting
     * everything above the anchor looks like.
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

        // A checkpoint pins one point, so on its own it says nothing about what came after it. A
        // chain that no longer reaches the anchored sequence has lost everything above it, which is
        // exactly the deletion an anchor is supposed to make visible.
        ChainHead head;
        try {
            head = store.head();
        } catch (MalformedRecordException e) {
            return VerificationResult.broken(0L, FailureReason.CHAIN_HEAD_MISMATCH);
        }
        if (head.lastSequence() < checkpoint.sequence()) {
            return VerificationResult.broken(checkpoint.sequence(), FailureReason.TRUNCATED);
        }

        List<ChainedRecord> anchored;
        try {
            anchored = store.findRange(checkpoint.sequence(), 1);
        } catch (MalformedRecordException e) {
            return VerificationResult.broken(checkpoint.sequence(), FailureReason.UNREADABLE_RECORD);
        }
        if (anchored.isEmpty() || anchored.get(0).record().sequence() != checkpoint.sequence()) {
            return VerificationResult.broken(checkpoint.sequence(), FailureReason.CHECKPOINT_MISMATCH);
        }
        boolean matches = Hmac.constantTimeEquals(
                anchored.get(0).hash().getBytes(StandardCharsets.UTF_8),
                checkpoint.hash().getBytes(StandardCharsets.UTF_8));
        return matches
                ? VerificationResult.intact()
                : VerificationResult.broken(checkpoint.sequence(), FailureReason.CHECKPOINT_MISMATCH);
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
