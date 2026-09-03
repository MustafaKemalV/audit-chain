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
     * A stored record could not be read back into its original shape. Treated as a break rather than
     * an error, because unreadable bytes in an audit row are what tampering looks like.
     */
    UNREADABLE_RECORD
}
