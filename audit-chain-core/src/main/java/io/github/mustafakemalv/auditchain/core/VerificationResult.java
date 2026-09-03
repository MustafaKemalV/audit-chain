package io.github.mustafakemalv.auditchain.core;

/**
 * Outcome of verifying an audit chain. When {@link #valid()} is true the chain is intact and
 * {@link #brokenSequence()} is {@code -1}. Otherwise {@link #brokenSequence()} is the sequence
 * number of the first record that failed and {@link #reason()} says why.
 */
public record VerificationResult(boolean valid, long brokenSequence, FailureReason reason) {

    public VerificationResult {
        if (reason == null) {
            throw new IllegalArgumentException("reason is required");
        }
        // The javadoc above states what a valid result looks like; without these checks the record
        // accepted results that contradicted it, and adding the checks after publication would turn
        // working consumer code into an exception.
        if (valid && (brokenSequence != -1L || reason != FailureReason.NONE)) {
            throw new IllegalArgumentException("an intact result cannot name a broken sequence or reason");
        }
        if (!valid && reason == FailureReason.NONE) {
            throw new IllegalArgumentException("a broken result must give a reason");
        }
    }


    public static VerificationResult intact() {
        return new VerificationResult(true, -1L, FailureReason.NONE);
    }

    public static VerificationResult broken(long brokenSequence, FailureReason reason) {
        return new VerificationResult(false, brokenSequence, reason);
    }
}
