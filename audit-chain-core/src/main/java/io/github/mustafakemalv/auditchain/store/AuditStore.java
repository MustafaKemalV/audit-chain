package io.github.mustafakemalv.auditchain.store;

import io.github.mustafakemalv.auditchain.core.ChainHead;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Storage SPI for the audit chain. The contract is deliberately append-only: there is no update or
 * delete method, so the API surface itself states "records are never changed in place". An
 * implementation backed by a real database should reinforce this at the storage layer (for example
 * an INSERT-only role that cannot UPDATE or DELETE).
 *
 * <h2>What an implementation must guarantee</h2>
 *
 * <p><b>Sealing is one atomic step.</b> {@link #appendSealed(RecordSealer)} reads the tip, hands it
 * to the chain to seal a record, and stores the result. Those three cannot be split: two writers
 * that both read the tip before either has written compute the same sequence number, and one of them
 * loses its record. That is why there is no plain "store this record" method to implement by
 * mistake. A store reachable from more than one thread or process must make the whole call
 * exclusive, typically with a row lock held until the write commits.
 *
 * <p><b>Unique sequence numbers.</b> This is the one failure the chain can neither verify for itself
 * nor recover from. Two records sharing a sequence is a forked chain, and every later verification
 * reports it as tampering that never happened. Reject a duplicate with {@link AuditStoreException};
 * accepting one silently is the worst thing a store can do, because it corrupts the log while
 * looking like an attack.
 *
 * <p><b>A durable high-water mark.</b> {@link #head()} reports how many records the chain has ever
 * held, and verification compares that against the records actually present. It is the only way to
 * notice records deleted from the end, because what remains after such a deletion is a shorter but
 * perfectly valid chain. A store that cannot keep a count outliving its records must say so in its
 * own documentation, because truncation is then undetectable through it.
 *
 * <p><b>Thread safety.</b> A store is shared and reached from several threads. Reads may run while
 * an append is in flight and must not break or return a partially written view.
 *
 * <p><b>Exception translation.</b> Failures reaching the backend must surface as
 * {@link AuditStoreException}, and a record that comes back corrupt as
 * {@link MalformedRecordException}. Letting a backend-specific exception escape forces callers to
 * catch the exception type of whichever store happens to be configured, which is precisely what this
 * SPI exists to avoid.
 */
public interface AuditStore {

    /**
     * Turns the current tip of a chain into the record to store.
     *
     * <p>This is where the chain computes the hash, which is why it cannot happen before the tip is
     * read: the record links to whatever sits at the end of the chain right now.
     */
    @FunctionalInterface
    interface RecordSealer {

        /**
         * Seals a record against the given tip.
         *
         * @param head the current tip of the chain
         * @return the record to store, taking {@link ChainHead#nextSequence()} as its sequence
         */
        ChainedRecord seal(ChainHead head);
    }

    /**
     * Reads the tip, seals one record against it, and stores that record, as a single atomic step.
     *
     * <p>This is the only way to write, and deliberately not something an implementation can get
     * half right. Splitting the read from the write is what loses records under concurrency, and a
     * lock taken around only the write protects nothing, because the tip was read outside it.
     *
     * <p>A store backed by a database should run the whole call in one transaction, joining the
     * caller's if there is one, and take a row lock while reading the tip. Outside a transaction that
     * lock is released the moment the read finishes and stops protecting anything.
     *
     * @param sealer turns the current tip into the record to append
     * @return the record that was stored
     * @throws AuditStoreException if the store cannot be reached, or rejects the write, including a
     *     duplicate sequence number
     */
    ChainedRecord appendSealed(RecordSealer sealer);

    /**
     * The tip of the chain: where the next record attaches, and how many records have ever been
     * appended.
     *
     * <p>The record count must survive the records themselves. Deriving it from the rows currently
     * present makes truncation invisible, because such a count always agrees with whatever is left.
     *
     * @return the current tip, or {@link ChainHead#empty()} for a chain never written to
     * @throws AuditStoreException if the store cannot be reached
     */
    ChainHead head();

    /**
     * A slice of the chain in ascending sequence order, so a long log can be verified in batches
     * without holding all of it in memory.
     *
     * @param fromSequence lowest sequence number to include
     * @param limit maximum number of records to return, must be positive
     * @return up to {@code limit} records with a sequence at or above {@code fromSequence}
     * @throws IllegalArgumentException if {@code limit} is not positive
     * @throws AuditStoreException if the store cannot be reached
     * @throws MalformedRecordException if a stored record cannot be read back
     */
    List<ChainedRecord> findRange(long fromSequence, int limit);

    /**
     * Number of records currently stored.
     *
     * <p>This counts what is actually there, unlike {@link ChainHead#recordCount()}, which remembers
     * what there has ever been. Verification compares the two, so a store must not answer this from
     * the same remembered value.
     *
     * @return how many records the store holds
     * @throws AuditStoreException if the store cannot be reached
     */
    long count();

    /**
     * The most recently appended record, or empty if the chain has none.
     *
     * <p>Derived from {@link #head()} and {@link #findRange(long, int)} so it cannot disagree with
     * them. Override only to save a round trip.
     *
     * @return the newest record, or empty
     * @throws AuditStoreException if the store cannot be reached
     * @throws MalformedRecordException if the stored record cannot be read back
     */
    default Optional<ChainedRecord> last() {
        ChainHead head = head();
        if (head.isEmpty()) {
            return Optional.empty();
        }
        List<ChainedRecord> found = findRange(head.lastSequence(), 1);
        return found.isEmpty() ? Optional.empty() : Optional.of(found.get(0));
    }

    /**
     * Every record, oldest first.
     *
     * <p>Derived by paging through {@link #findRange(long, int)}, so it holds the whole chain in
     * memory by definition. Verification does not use it; it is here for callers exporting or
     * inspecting a chain small enough to fit.
     *
     * @return every record, oldest first
     * @throws AuditStoreException if the store cannot be reached
     * @throws MalformedRecordException if a stored record cannot be read back
     */
    default List<ChainedRecord> findAll() {
        List<ChainedRecord> all = new ArrayList<>();
        long from = 0L;
        while (true) {
            List<ChainedRecord> page = findRange(from, 1000);
            if (page.isEmpty()) {
                return all;
            }
            all.addAll(page);
            from = page.get(page.size() - 1).record().sequence() + 1;
        }
    }
}
