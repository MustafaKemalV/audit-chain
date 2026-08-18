package io.github.mustafakemalv.auditchain.store;

import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * In-memory {@link AuditStore} backed by a synchronized list. Intended for tests and demos, not for
 * production durability. Reads return copies so callers cannot mutate the backing list.
 */
public class InMemoryAuditStore implements AuditStore {

    private final List<ChainedRecord> records = new ArrayList<>();

    @Override
    public synchronized void append(ChainedRecord record) {
        records.add(record);
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
    public synchronized long count() {
        return records.size();
    }
}
