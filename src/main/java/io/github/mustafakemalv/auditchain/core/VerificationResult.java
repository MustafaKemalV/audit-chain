package io.github.mustafakemalv.auditchain.core;

/**
 * Outcome of verifying an audit chain. When {@link #valid()} is true the chain is intact and
 * {@link #brokenSequence()} is {@code -1}. Otherwise {@link #brokenSequence()} is the sequence
 * number of the first record that failed and {@link #reason()} says why.
 */
public record VerificationResult(boolean valid, long brokenSequence, FailureReason reason) {

    public static VerificationResult intact() {
        return new VerificationResult(true, -1L, FailureReason.NONE);
    }

    public static VerificationResult broken(long brokenSequence, FailureReason reason) {
        return new VerificationResult(false, brokenSequence, reason);
    }
}
