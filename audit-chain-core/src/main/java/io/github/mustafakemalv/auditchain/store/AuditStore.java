package io.github.mustafakemalv.auditchain.store;

import io.github.mustafakemalv.auditchain.core.ChainHead;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * Storage SPI for the audit chain. The contract is deliberately append-only: there is no update or
 * delete method, so the API surface itself states "records are never changed in place". An
 * implementation backed by a real database should reinforce this at the storage layer (for example
 * an INSERT-only role that cannot UPDATE or DELETE).
 *
 * <h2>What an implementation must guarantee</h2>
 *
 * <p><b>Unique sequence numbers.</b> This is the one requirement the chain cannot verify for itself
 * and cannot recover from. Two records sharing a sequence number is a forked chain, and every later
 * verification reports it as tampering that never happened. The bundled JDBC store gets this from a
 * primary key on the sequence column; an implementation without an equivalent constraint must reject
 * a duplicate sequence itself, by raising {@link AuditStoreException}. Silently accepting one is the
 * worst failure available to a store, because it corrupts the log while looking like an attack.
 *
 * <p><b>Thread safety.</b> A store is shared and reached from several threads. {@code append} is
 * serialized by the chain, but {@code last}, {@code findAll}, {@code findRange} and {@code count}
 * are not, so they may run while an append is in flight and must not break or return a partially
 * written view.
 *
 * <p><b>Exception translation.</b> Failures reaching the backend must surface as
 * {@link AuditStoreException}, and a record that comes back corrupt must surface as
 * {@link MalformedRecordException}. Letting a backend-specific exception escape forces callers to
 * catch the exception type of whichever store happens to be configured, which is precisely what this
 * SPI exists to avoid.
 */
public interface AuditStore {

    /**
     * Appends {@code record} as the new head of the chain.
     *
     * @param record the record to store
     * @throws AuditStoreException if the store cannot be reached or rejects the write, including a
     *     duplicate sequence number
     */
    void append(ChainedRecord record);

    /**
     * The current head (most recently appended record), or empty if the chain has no records.
     *
     * @return the head record, or empty
     * @throws AuditStoreException if the store cannot be reached
     * @throws MalformedRecordException if the stored head cannot be read back
     */
    Optional<ChainedRecord> last();

    /**
     * All records in ascending sequence order, as needed to verify the chain.
     *
     * <p>This loads the whole chain into memory. It is fine for the sizes most applications reach,
     * but a long-lived log should be verified with {@link #findRange(long, int)} instead.
     *
     * @return every record, oldest first
     * @throws AuditStoreException if the store cannot be reached
     * @throws MalformedRecordException if a stored record cannot be read back
     */
    List<ChainedRecord> findAll();

    /**
     * A slice of the chain in ascending sequence order, so a long log can be verified in batches
     * without holding all of it in memory.
     *
     * <p>The default implementation goes through {@link #findAll()}, which defeats the purpose; a
     * store backed by a database should replace it with a query that actually limits what it reads.
     * It exists as a default so that adding this method does not break implementations written
     * against an earlier version.
     *
     * @param fromSequence lowest sequence number to include
     * @param limit maximum number of records to return, must be positive
     * @return up to {@code limit} records with a sequence at or above {@code fromSequence}
     * @throws IllegalArgumentException if {@code limit} is not positive
     * @throws AuditStoreException if the store cannot be reached
     * @throws MalformedRecordException if a stored record cannot be read back
     */
    default List<ChainedRecord> findRange(long fromSequence, int limit) {
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be positive");
        }
        List<ChainedRecord> slice = new ArrayList<>();
        for (ChainedRecord record : findAll()) {
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

    /**
     * The tip of the chain: where the next record attaches, and how many records have ever been
     * appended.
     *
     * <p>The default derives it from {@link #last()} and {@link #count()}, which is correct but
     * cannot notice a truncated chain: a count taken from the rows that remain always agrees with
     * those rows. A store that can keep a durable high-water mark should do so and report it here,
     * because that is what turns "records were deleted from the end" from invisible into detectable.
     *
     * @param genesisHash the value an empty chain's first record links to
     * @return the current tip
     * @throws AuditStoreException if the store cannot be reached
     */
    default ChainHead head(String genesisHash) {
        return last()
                .map(record -> new ChainHead(record.record().sequence(), record.hash(), count()))
                .orElseGet(() -> ChainHead.empty(genesisHash));
    }

    /**
     * The tip of the chain, read in a way that serializes concurrent appends until the caller's work
     * is committed.
     *
     * <p>A hash chain cannot be built in parallel: a record cannot be sealed until the one before it
     * is settled, so two appends that both read the same tip will compute the same sequence number
     * and one of them must lose. A store backed by a database should take a row lock here, which
     * turns that collision into an orderly queue. The default simply reads, which is right for a
     * store whose appends are already serialized in memory.
     *
     * @param genesisHash the value an empty chain's first record links to
     * @return the current tip
     * @throws AuditStoreException if the store cannot be reached
     */
    default ChainHead lockHead(String genesisHash) {
        return head(genesisHash);
    }

    /**
     * Seals and stores one record as a single unit of work.
     *
     * <p>Reading the tip and writing the record have to be one atomic step. Split apart, two writers
     * can both read the same tip before either has written, compute the same sequence number, and
     * one of them loses its record. A row lock alone does not fix that: outside a transaction the
     * lock is released the moment the read finishes, so the guarantee quietly disappears exactly
     * when nobody is looking.
     *
     * <p>{@code sealer} receives the current tip and returns the record to store, which is where the
     * chain computes the hash. A store backed by a database should run the whole call in one
     * transaction, joining the caller's if there is one.
     *
     * @param genesisHash the value an empty chain's first record links to
     * @param sealer turns the current tip into the record to append
     * @return the record that was stored
     * @throws AuditStoreException if the store cannot be reached or rejects the write
     */
    default ChainedRecord appendSealed(String genesisHash, Function<ChainHead, ChainedRecord> sealer) {
        ChainHead head = lockHead(genesisHash);
        ChainedRecord sealed = sealer.apply(head);
        append(sealed);
        return sealed;
    }

    /**
     * Number of records currently stored.
     *
     * <p>Deliberately not given a default: verification uses this count to notice records missing
     * from the end of the chain, which is the one kind of tampering the hash links cannot reveal on
     * their own. A default in terms of {@link #findAll()} would quietly make that check as expensive
     * as reading the entire log, so each store is asked to answer it properly.
     *
     * @return how many records the store holds
     * @throws AuditStoreException if the store cannot be reached
     */
    long count();
}
