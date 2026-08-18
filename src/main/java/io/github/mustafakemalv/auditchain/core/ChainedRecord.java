package io.github.mustafakemalv.auditchain.core;

/**
 * One node in the audit chain: the {@link AuditRecord} that describes what happened, plus its
 * position in the chain, the hash of the previous node and this node's own hash. This is the unit an
 * {@code AuditStore} persists and reads. Both hashes are lowercase hex strings.
 */
public record ChainedRecord(AuditRecord record, String previousHash, String hash) {

    public ChainedRecord {
        if (record == null) {
            throw new IllegalArgumentException("record is required");
        }
        if (previousHash == null) {
            throw new IllegalArgumentException("previousHash is required");
        }
        if (hash == null) {
            throw new IllegalArgumentException("hash is required");
        }
    }
}
