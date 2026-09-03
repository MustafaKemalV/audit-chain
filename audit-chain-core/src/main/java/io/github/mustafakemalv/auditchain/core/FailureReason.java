package io.github.mustafakemalv.auditchain.core;

/** Why a {@link VerificationResult} judged a chain broken, or {@link #NONE} when it is intact. */
public enum FailureReason {

    /** The chain is intact. */
    NONE,

    /** A record's recomputed hash does not match the stored hash (its content was altered). */
    HASH_MISMATCH,

    /** A record's previousHash does not point at the previous record's hash. */
    BROKEN_LINK,

    /** A sequence number is missing or out of order (a record was removed or reordered). */
    SEQUENCE_GAP,

    /** The chain is internally consistent but does not match an externally anchored checkpoint. */
    CHECKPOINT_MISMATCH,

    /**
     * Records are missing from the end of the chain. The hash links cannot reveal this on their own,
     * because what is left is still a valid shorter chain; it is caught by comparing the records
     * present against the high-water mark the chain reached.
     */
    TRUNCATED,

    /**
     * The chain's stored tip contradicts the records themselves, most plainly when the tip is gone
     * while records remain. That combination is never a fresh chain; it is a deleted tip row, a
     * restore of one table without the other, or a migration that ran on a chain that already had
     * history. It matters because the tip is what remembers how long the chain has been, so a chain
     * that has lost it can no longer show that records were removed from the end.
     */
    CHAIN_HEAD_MISMATCH,

    /**
     * A stored record could not be read back into its original shape. Treated as a break rather than
     * an error, because unreadable bytes in an audit row are what tampering looks like.
     */
    UNREADABLE_RECORD
}
