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
    SEQUENCE_GAP
}
