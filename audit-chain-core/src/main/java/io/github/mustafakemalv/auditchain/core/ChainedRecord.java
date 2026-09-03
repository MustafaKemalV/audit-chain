package io.github.mustafakemalv.auditchain.core;

/**
 * One node in the audit chain: the {@link AuditRecord} that describes what happened, plus its
 * position in the chain, the hash of the previous node and this node's own hash. This is the unit an
 * {@code AuditStore} persists and reads. Both hashes are lowercase hex strings.
 *
 * <p>Each node also carries the {@code formatVersion} its hash was computed under, so a chain
 * written by an older build stays verifiable after the encoding changes. A store must persist this
 * value alongside the hashes and hand it back on read; inventing it on the way out would make every
 * older record look tampered with.
 *
 * @param record what happened
 * @param previousHash the hash of the preceding node, or the genesis value for the first node
 * @param hash this node's own hash
 * @param formatVersion the canonical encoding version this node's hash was computed under
 */
public record ChainedRecord(AuditRecord record, String previousHash, String hash, int formatVersion) {

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
        if (formatVersion <= 0) {
            throw new IllegalArgumentException("formatVersion must be positive");
        }
    }

    /**
     * Creates a node stamped with the format version this build writes.
     *
     * <p>Deliberately a named factory rather than a constructor. A store reading a row back must
     * carry the version stored with it; stamping the current version there instead would mark every
     * older record as written under a format it was not, and after the encoding next changes those
     * records would all report as tampered with. Naming the operation makes that a decision rather
     * than the shortest thing to type.
     *
     * @param record what happened
     * @param previousHash the hash of the preceding node
     * @param hash this node's own hash
     * @return a node carrying {@link CanonicalEncoder#currentFormatVersion()}
     */
    public static ChainedRecord currentFormat(AuditRecord record, String previousHash, String hash) {
        return new ChainedRecord(record, previousHash, hash, CanonicalEncoder.currentFormatVersion());
    }
}
