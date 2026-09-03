package io.github.mustafakemalv.auditchain.store;

import io.github.mustafakemalv.auditchain.core.ChainHead;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * In-memory {@link AuditStore}, kept in an {@code ArrayList} guarded by this object's monitor.
 * Intended for tests and demos, not for production durability: the log does not survive a restart.
 * Reads return copies so callers cannot mutate the backing list.
 *
 * <p>Like the JDBC store, it refuses a repeated sequence number. Without that check the SPI's one
 * unrecoverable failure, a forked chain, would be silently possible here while the JDBC store rejects
 * it, and code that verified fine against this store would break against a real database.
 */
public class InMemoryAuditStore implements AuditStore {

    private final List<ChainedRecord> records = new ArrayList<>();

    /** Only ever grows, so verification can still tell that records went missing from the end. */
    private long highWaterMark;

    /** Creates an empty store. */
    public InMemoryAuditStore() {
    }

    @Override
    public synchronized void append(ChainedRecord record) {
        if (record == null) {
            throw new IllegalArgumentException("record is required");
        }
        long sequence = record.record().sequence();
        // The JDBC store gets this from a primary key. Enforcing it here too keeps the two stores
        // behaving the same way under a race, instead of one corrupting quietly and one erroring.
        if (!records.isEmpty() && sequence <= records.get(records.size() - 1).record().sequence()) {
            throw new AuditStoreException(
                    "sequence " + sequence + " is not above the current head; the chain would fork");
        }
        records.add(record);
        highWaterMark++;
    }

    @Override
    public synchronized Optional<ChainedRecord> last() {
        if (records.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(records.get(records.size() - 1));
    }

    @Override
    public synchronized List<ChainedRecord> findAll() {
        return new ArrayList<>(records);
    }

    @Override
    public synchronized List<ChainedRecord> findRange(long fromSequence, int limit) {
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be positive");
        }
        List<ChainedRecord> slice = new ArrayList<>();
        for (ChainedRecord record : records) {
            if (record.record().sequence() < fromSequence) {
                continue;
            }
            slice.add(record);
            if (slice.size() == limit) {
                break;
            }
        }
        return slice;
    }

    @Override
    public synchronized ChainHead head(String genesisHash) {
        if (records.isEmpty()) {
            return new ChainHead(-1L, genesisHash, highWaterMark);
        }
        ChainedRecord last = records.get(records.size() - 1);
        return new ChainHead(last.record().sequence(), last.hash(), highWaterMark);
    }

    @Override
    public synchronized long count() {
        return records.size();
    }
}
