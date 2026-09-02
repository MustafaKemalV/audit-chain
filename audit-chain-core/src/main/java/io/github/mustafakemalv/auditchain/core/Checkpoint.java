package io.github.mustafakemalv.auditchain.core;

/**
 * A snapshot of the chain's position: the sequence number of a record and its hash. Export a
 * checkpoint with {@code AuditChain.head()} and anchor it in a separate trust domain; later,
 * {@code AuditChain.verifyAgainstCheckpoint(...)} can detect a rewrite that an internal verify cannot
 * (for example one made with a stolen key), because the rewritten hash no longer matches the
 * externally anchored one.
 */
public record Checkpoint(long sequence, String hash) {

    public Checkpoint {
        if (hash == null) {
            throw new IllegalArgumentException("hash is required");
        }
    }
}
