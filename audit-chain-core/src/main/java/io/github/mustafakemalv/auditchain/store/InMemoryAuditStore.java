package io.github.mustafakemalv.auditchain.store;

import io.github.mustafakemalv.auditchain.core.ChainHead;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import java.util.ArrayList;
import java.util.List;

/**
 * In-memory {@link AuditStore}, kept in an {@code ArrayList} guarded by this object's monitor.
 * Intended for tests and demos, not for production durability: the log does not survive a restart.
 * Reads return copies so callers cannot mutate the backing list.
 *
 * <p>Like the JDBC store, it refuses a sequence that does not move forward, and it keeps a
 * high-water mark that outlives the records, so a chain emptied through {@link #clear()} is still
 * reported as truncated rather than as a fresh chain.
 */
public class InMemoryAuditStore implements AuditStore {

    private final List<ChainedRecord> records = new ArrayList<>();

    /** Only ever grows, so verification can still tell that records went missing from the end. */
    private long highWaterMark;

    /** Creates an empty store. */
    public InMemoryAuditStore() {
    }

    @Override
    public synchronized ChainedRecord appendSealed(RecordSealer sealer) {
        if (sealer == null) {
            throw new IllegalArgumentException("sealer is required");
        }
        // The monitor spans reading the tip and storing the record, which is exactly the atomicity
        // the SPI asks for. A store split across processes needs a row lock instead.
        ChainedRecord sealed = sealer.seal(head());
        store(sealed);
        return sealed;
    }

    /**
     * Stores a record directly, without sealing it against the current tip.
     *
     * <p>Deliberately not part of the SPI: writing without reading the tip in the same step is how
     * concurrent appends lose records. It is here so tests can stage a chain, including a deliberately
     * broken one.
     *
     * @param record the record to store
     * @throws IllegalArgumentException if the record is null
     * @throws AuditStoreException if its sequence does not move the chain forward
     */
    public synchronized void append(ChainedRecord record) {
        store(record);
    }

    private void store(ChainedRecord record) {
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

    /**
     * Removes every record while keeping the high-water mark, standing in for someone deleting rows
     * from the table underneath the chain.
     */
    public synchronized void clear() {
        records.clear();
    }

    @Override
    public synchronized ChainHead head() {
        if (records.isEmpty()) {
            return ChainHead.emptyWithHistory(highWaterMark);
        }
        ChainedRecord last = records.get(records.size() - 1);
        return new ChainHead(last.record().sequence(), last.hash(), highWaterMark);
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
    public synchronized List<ChainedRecord> findAll() {
        return new ArrayList<>(records);
    }

    @Override
    public synchronized long count() {
        return records.size();
    }
}
