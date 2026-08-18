package io.github.mustafakemalv.auditchain.store;

import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import java.util.List;
import java.util.Optional;

/**
 * Storage SPI for the audit chain. The contract is deliberately append-only: there is no update or
 * delete method, so the API surface itself states "records are never changed in place". An
 * implementation backed by a real database should reinforce this at the storage layer (for example
 * an INSERT-only role that cannot UPDATE or DELETE).
 */
public interface AuditStore {

    /** Appends {@code record} as the new head of the chain. */
    void append(ChainedRecord record);

    /** The current head (most recently appended record), or empty if the chain has no records. */
    Optional<ChainedRecord> last();

    /** All records in ascending sequence order, as needed to verify the chain. */
    List<ChainedRecord> findAll();

    /** Number of records currently stored. */
    long count();
}
