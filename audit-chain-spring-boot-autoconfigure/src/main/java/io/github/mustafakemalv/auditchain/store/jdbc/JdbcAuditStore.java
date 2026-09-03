package io.github.mustafakemalv.auditchain.store.jdbc;

import io.github.mustafakemalv.auditchain.core.AuditRecord;
import io.github.mustafakemalv.auditchain.core.ChainHead;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import io.github.mustafakemalv.auditchain.store.AuditStore;
import io.github.mustafakemalv.auditchain.store.AuditStoreException;
import io.github.mustafakemalv.auditchain.store.DetailsCodec;
import java.sql.PreparedStatement;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * JDBC-backed {@link AuditStore} that appends each record as one row via {@link JdbcTemplate}. The
 * table is treated as append-only: this class only ever INSERTs and SELECTs. To make that a real
 * guarantee, grant the audit database role INSERT and SELECT but not UPDATE or DELETE.
 *
 * <p>The timestamp is stored as epoch milliseconds so it round-trips exactly (the chain truncates
 * timestamps to milliseconds when appending), and the details map is stored in one column via
 * {@link DetailsCodec}.
 *
 * <p>Unique sequence numbers, which the SPI requires and the chain depends on, come from the primary
 * key on the sequence column in the shipped schema. A concurrent append that loses the race is
 * rejected by that constraint and surfaces as {@link AuditStoreException} rather than forking the
 * chain.
 *
 * <p>This class is stateless and safe to share between threads. It takes part in whatever
 * transaction the calling thread already has, because {@code JdbcTemplate} uses the connection bound
 * to that transaction: an append made inside a business transaction commits and rolls back with it.
 */
public class JdbcAuditStore implements AuditStore {

    private static final Pattern SAFE_TABLE_NAME = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]*$");
    private static final int MAX_DETAILS_LENGTH = 4000;

    /** Default name of the table holding one tip row per audit table. */
    public static final String DEFAULT_HEAD_TABLE = "audit_chain_head";

    /** Width of the VARCHAR columns holding actor, action, resource type and resource id. */
    private static final int MAX_STRING_LENGTH = 255;

    private static final RowMapper<ChainedRecord> ROW_MAPPER = (rs, rowNum) -> {
        AuditRecord record = new AuditRecord(
                rs.getLong("sequence"),
                Instant.ofEpochMilli(rs.getLong("timestamp_ms")),
                rs.getString("actor"),
                rs.getString("action"),
                rs.getString("resource_type"),
                rs.getString("resource_id"),
                DetailsCodec.decode(rs.getString("details")));
        return new ChainedRecord(
                record,
                rs.getString("previous_hash"),
                rs.getString("hash"),
                rs.getInt("format_version"));
    };

    private final JdbcTemplate jdbcTemplate;
    private final String tableName;
    private final String headTableName;
    private final TransactionTemplate transactionTemplate;
    /** Used when the caller's transaction cannot accept a write; see {@link #appendSealed}. */
    private final TransactionTemplate independentTransactionTemplate;
    /** Set once the tip row is known to exist; see {@link #ensureHeadRowExists()}. */
    private volatile boolean headRowExists;

    /**
     * Creates a store over {@code tableName}.
     *
     * @param jdbcTemplate the template to run statements through
     * @param tableName the audit table, which must be a plain identifier
     * @throws IllegalArgumentException if the template is null or the table name is not a plain
     *     identifier
     */
    public JdbcAuditStore(JdbcTemplate jdbcTemplate, String tableName) {
        this(jdbcTemplate, tableName, DEFAULT_HEAD_TABLE, null);
    }

    /**
     * Creates a store over {@code tableName}, tracking its tip in {@code headTableName}.
     *
     * @param jdbcTemplate the template to run statements through
     * @param tableName the audit table, which must be a plain identifier
     * @param headTableName the table holding one tip row per audit table
     * @throws IllegalArgumentException if the template is null or either name is not a plain
     *     identifier
     */
    public JdbcAuditStore(JdbcTemplate jdbcTemplate, String tableName, String headTableName) {
        this(jdbcTemplate, tableName, headTableName, null);
    }

    /**
     * Creates a store over {@code tableName}, tracking its tip in {@code headTableName}.
     *
     * @param jdbcTemplate the template to run statements through
     * @param tableName the audit table, which must be a plain identifier
     * @param headTableName the table holding one tip row per audit table
     * @throws IllegalArgumentException if the template is null or either name is not a plain
     *     identifier
     */
    public JdbcAuditStore(JdbcTemplate jdbcTemplate, String tableName, String headTableName,
            PlatformTransactionManager transactionManager) {
        if (jdbcTemplate == null) {
            throw new IllegalArgumentException("jdbcTemplate is required");
        }
        // The table name cannot be a bind parameter, so it is concatenated into the SQL. Validate it
        // strictly to keep that concatenation safe from injection.
        if (tableName == null || !SAFE_TABLE_NAME.matcher(tableName).matches()) {
            throw new IllegalArgumentException("tableName must match " + SAFE_TABLE_NAME.pattern());
        }
        if (headTableName == null || !SAFE_TABLE_NAME.matcher(headTableName).matches()) {
            throw new IllegalArgumentException("headTableName must match " + SAFE_TABLE_NAME.pattern());
        }
        this.jdbcTemplate = jdbcTemplate;
        this.tableName = tableName;
        this.headTableName = headTableName;
        // Prefer the application's own transaction manager. Building one here from the DataSource
        // looks equivalent and is not: Spring joins an existing transaction only when it finds a
        // connection bound under that same DataSource object, so a JTA setup, a JPA manager with no
        // DataSource set, or a proxy-wrapped one would silently start a SECOND transaction on a
        // second connection. The audit record would then commit before the business data and survive
        // its rollback, which is the one thing this library promises cannot happen.
        PlatformTransactionManager resolved = transactionManager;
        if (resolved == null) {
            if (jdbcTemplate.getDataSource() == null) {
                throw new IllegalArgumentException(
                        "jdbcTemplate has no DataSource, so appends could not be made atomic");
            }
            resolved = new DataSourceTransactionManager(jdbcTemplate.getDataSource());
        }
        // Default propagation joins the caller's transaction when there is one and starts its own
        // when there is not. That second case matters: outside a transaction the row lock taken
        // while reading the tip is released immediately and protects nothing.
        this.transactionTemplate = new TransactionTemplate(resolved);
        this.independentTransactionTemplate = new TransactionTemplate(resolved);
        this.independentTransactionTemplate.setPropagationBehavior(
                TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @Override
    public ChainedRecord appendSealed(RecordSealer sealer) {
        if (sealer == null) {
            throw new IllegalArgumentException("sealer is required");
        }
        ensureHeadRowExists();
        // A read-only transaction cannot carry this write at all: the database refuses both the row
        // lock and the insert. Auditing a read ("who viewed this record") is a normal thing to want,
        // so the write goes into its own transaction rather than failing. It could not share the
        // reader's fate anyway, because a read has no fate to share.
        if (TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
            return appendSealedIndependently(sealer);
        }
        return transactionTemplate.execute(status -> sealAndInsert(sealer));
    }

    /**
     * Seals and stores a record in a transaction of its own, whatever the caller is doing.
     *
     * <p>Used where the audit write must not be able to affect the caller's transaction, which is
     * the deliberate trade in {@code audit-chain.on-failure=LOG}: the record no longer shares the
     * business operation's fate in either direction.
     *
     * @param sealer turns the current tip into the record to append
     * @return the record that was stored
     */
    @Override
    public ChainedRecord appendSealedIndependently(RecordSealer sealer) {
        if (sealer == null) {
            throw new IllegalArgumentException("sealer is required");
        }
        ensureHeadRowExists();
        return independentTransactionTemplate.execute(status -> sealAndInsert(sealer));
    }

    /** The write itself, always called with a transaction already in progress. */
    private ChainedRecord sealAndInsert(RecordSealer sealer) {
        ChainHead head = readHead(true);
        ChainedRecord sealed = sealer.seal(head);
        insert(sealed);
        return sealed;
    }

    /**
     * Writes one record and moves the tip, both inside the caller's transaction. Private because the
     * SPI deliberately offers no way to store a record without having just read the tip.
     */
    private void insert(ChainedRecord record) {
        AuditRecord r = record.record();
        String encodedDetails = DetailsCodec.encode(r.details());
        // Fail fast instead of letting a non-strict database silently truncate a column. A truncated
        // value no longer re-hashes to the stored hash, so the record reports as tampered with from
        // then on, permanently and indistinguishably from a real attack. MySQL outside strict mode
        // does exactly this without a word.
        if (encodedDetails.length() > MAX_DETAILS_LENGTH) {
            throw new IllegalArgumentException(
                    "encoded details exceed the " + MAX_DETAILS_LENGTH + "-character column limit");
        }
        checkLength("actor", r.actor());
        checkLength("action", r.action());
        checkLength("resourceType", r.resourceType());
        checkLength("resourceId", r.resourceId());
        try {
            jdbcTemplate.update(
                    "INSERT INTO " + tableName + " (sequence, format_version, timestamp_ms, actor,"
                            + " action, resource_type, resource_id, details, previous_hash, hash)"
                            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    r.sequence(),
                    record.formatVersion(),
                    r.timestamp().toEpochMilli(),
                    r.actor(),
                    r.action(),
                    r.resourceType(),
                    r.resourceId(),
                    encodedDetails,
                    record.previousHash(),
                    record.hash());
            // Move the tip in the same transaction as the record. If these could drift apart, the
            // high-water mark would either miss real records or claim records that never existed.
            int updated = jdbcTemplate.update(
                    "UPDATE " + headTableName + " SET last_sequence = ?, last_hash = ?,"
                            + " record_count = record_count + 1, updated_ms = ? WHERE chain_table = ?",
                    r.sequence(), record.hash(), System.currentTimeMillis(), tableName);
            if (updated == 0) {
                jdbcTemplate.update(
                        "INSERT INTO " + headTableName + " (chain_table, last_sequence, last_hash,"
                                + " record_count, updated_ms) VALUES (?, ?, ?, ?, ?)",
                        tableName, r.sequence(), record.hash(), 1L, System.currentTimeMillis());
            }
        } catch (DataAccessException e) {
            // Includes the duplicate-sequence case: two appends raced and this one lost. The SPI
            // requires that to be an error rather than a second record on the same sequence.
            throw new AuditStoreException(describeAppendFailure(r.sequence()), e);
        }
    }

    private static void checkLength(String field, String value) {
        if (value != null && value.length() > MAX_STRING_LENGTH) {
            throw new IllegalArgumentException(field + " is " + value.length() + " characters, above the "
                    + MAX_STRING_LENGTH + "-character column limit");
        }
    }

    /**
     * Creates this chain's tip row if it is not there yet, so the row lock has something to take.
     *
     * <p>The shipped schema seeds a row for the default table name, but the table name is
     * configurable, so any other chain would start without one. A lock on nothing takes nothing, and
     * the first appends on such a chain raced each other exactly as they did before the tip existed.
     *
     * <p>Written as INSERT ... WHERE NOT EXISTS rather than an UPSERT because the UPSERT syntax
     * differs across databases, and because a single statement is safe against two writers arriving
     * together: one inserts, the other matches nothing and moves on.
     */
    private void ensureHeadRowExists() {
        if (headRowExists) {
            return;
        }
        synchronized (this) {
            if (headRowExists) {
                return;
            }
            try {
                // In a transaction of its own, and before the caller's begins. Inside the append
                // transaction two writers cannot see each other's uncommitted insert, so both would
                // try and one would lose the whole append to a duplicate key.
                independentTransactionTemplate.executeWithoutResult(status -> insertHeadRow());
            } catch (DataAccessException e) {
                // Another process created it between our check and our insert, which is the outcome
                // we wanted anyway.
            }
            headRowExists = true;
        }
    }

    private void insertHeadRow() {
        jdbcTemplate.update(
                "INSERT INTO " + headTableName + " (chain_table, last_sequence, last_hash,"
                        + " record_count, updated_ms) SELECT ?, ?, ?, ?, ?"
                        + " WHERE NOT EXISTS (SELECT 1 FROM " + headTableName + " WHERE chain_table = ?)",
                tableName, -1L, ChainHead.GENESIS_HASH, 0L, System.currentTimeMillis(), tableName);
    }

    @Override
    public ChainHead head() {
        return readHead(false);
    }

    private ChainHead readHead(boolean forUpdate) {
        String sql = "SELECT last_sequence, last_hash, record_count FROM " + headTableName
                + " WHERE chain_table = ?" + (forUpdate ? " FOR UPDATE" : "");
        try {
            Map<String, Object> row = jdbcTemplate.queryForMap(sql, tableName);
            return new ChainHead(
                    ((Number) row.get("last_sequence")).longValue(),
                    // CHAR(64) is blank-padded on some databases, so trim before it reaches a hash
                    // comparison.
                    ((String) row.get("last_hash")).trim(),
                    ((Number) row.get("record_count")).longValue());
        } catch (EmptyResultDataAccessException e) {
            // No tip row yet: this chain has never been appended to.
            return ChainHead.empty();
        } catch (DataAccessException e) {
            throw new AuditStoreException("could not read the tip of the audit chain", e);
        }
    }

    @Override
    public Optional<ChainedRecord> last() {
        try {
            ChainedRecord record = jdbcTemplate.queryForObject(
                    "SELECT * FROM " + tableName
                            + " WHERE sequence = (SELECT MAX(sequence) FROM " + tableName + ")",
                    ROW_MAPPER);
            return Optional.ofNullable(record);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        } catch (DataAccessException e) {
            throw new AuditStoreException("could not read the head of the audit chain", e);
        }
    }

    @Override
    public List<ChainedRecord> findAll() {
        try {
            return jdbcTemplate.query("SELECT * FROM " + tableName + " ORDER BY sequence ASC", ROW_MAPPER);
        } catch (DataAccessException e) {
            throw new AuditStoreException("could not read the audit chain", e);
        }
    }

    @Override
    public List<ChainedRecord> findRange(long fromSequence, int limit) {
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be positive");
        }
        // setMaxRows rather than a LIMIT clause: the row-limiting syntax differs between databases
        // (LIMIT on MySQL, FETCH FIRST on Oracle), while setMaxRows is plain JDBC and works on all
        // of them.
        String sql = "SELECT * FROM " + tableName + " WHERE sequence >= ? ORDER BY sequence ASC";
        try {
            return jdbcTemplate.query(connection -> {
                PreparedStatement statement = connection.prepareStatement(sql);
                statement.setLong(1, fromSequence);
                statement.setMaxRows(limit);
                return statement;
            }, ROW_MAPPER);
        } catch (DataAccessException e) {
            throw new AuditStoreException("could not read the audit chain from sequence " + fromSequence, e);
        }
    }

    /**
     * Explains a rejected append. A lost race and a tip row that has fallen behind the table produce
     * the same constraint violation, but the second repeats forever and stops the chain, so the
     * message names it rather than letting it look like ordinary contention.
     */
    private String describeAppendFailure(long sequence) {
        // Deliberately no diagnostic query: a failed insert has usually left the transaction unable
        // to run one, so asking would only produce a second, less useful error.
        return "could not append audit record " + sequence
                + ". If this repeats for the same sequence, the " + headTableName + " row for "
                + tableName + " has fallen behind the records and every append will keep colliding"
                + " until it is set past the table's highest sequence.";
    }

    @Override
    public long count() {
        try {
            Long count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM " + tableName, Long.class);
            return count == null ? 0L : count;
        } catch (DataAccessException e) {
            throw new AuditStoreException("could not count the audit records", e);
        }
    }
}
