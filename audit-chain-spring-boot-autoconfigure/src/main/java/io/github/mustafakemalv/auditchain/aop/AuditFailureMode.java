package io.github.mustafakemalv.auditchain.aop;

/**
 * What an {@link Audited} method does when the audit write itself fails.
 *
 * <p>A top-level type on purpose: this is bound from {@code audit-chain.on-failure}, and the
 * configuration metadata shipped in the jar records the type's fully qualified name permanently. As
 * a nested type it would tie a user-facing property to an internal class that could then never be
 * renamed or moved.
 */
public enum AuditFailureMode {

    /**
     * Let the failure propagate, so the business operation fails with it. Correct when the audit
     * record matters as much as the action itself.
     */
    FAIL,

    /**
     * Log the failure and let the business operation succeed unrecorded. Correct only where
     * availability outranks a complete audit log; say so deliberately.
     */
    LOG
}
