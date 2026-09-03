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
import java.util.function.Function;
import java.util.regex.Pattern;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
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

    /**
     * Creates a store over {@code tableName}.
     *
     * @param jdbcTemplate the template to run statements through
     * @param tableName the audit table, which must be a plain identifier
     * @throws IllegalArgumentException if the template is null or the table name is not a plain
     *     identifier
     */
    public JdbcAuditStore(JdbcTemplate jdbcTemplate, String tableName) {
        this(jdbcTemplate, tableName, DEFAULT_HEAD_TABLE);
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
        // Default propagation joins the caller's transaction when there is one and starts its own
        // when there is not. That second case is what matters: outside a transaction the row lock
        // taken while reading the tip would be released immediately and protect nothing.
        this.transactionTemplate = jdbcTemplate.getDataSource() == null
                ? null
                : new TransactionTemplate(new DataSourceTransactionManager(jdbcTemplate.getDataSource()));
    }

    @Override
    public ChainedRecord appendSealed(String genesisHash, Function<ChainHead, ChainedRecord> sealer) {
        if (transactionTemplate == null) {
            return AuditStore.super.appendSealed(genesisHash, sealer);
        }
        return transactionTemplate.execute(status -> {
            ChainHead head = lockHead(genesisHash);
            ChainedRecord sealed = sealer.apply(head);
            append(sealed);
            return sealed;
        });
    }

    @Override
    public void append(ChainedRecord record) {
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
            throw new AuditStoreException("could not append audit record " + r.sequence(), e);
        }
    }

    private static void checkLength(String field, String value) {
        if (value != null && value.length() > MAX_STRING_LENGTH) {
            throw new IllegalArgumentException(field + " is " + value.length() + " characters, above the "
                    + MAX_STRING_LENGTH + "-character column limit");
        }
    }

    @Override
    public ChainHead head(String genesisHash) {
        return readHead(genesisHash, false);
    }

    @Override
    public ChainHead lockHead(String genesisHash) {
        return readHead(genesisHash, true);
    }

    private ChainHead readHead(String genesisHash, boolean forUpdate) {
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
            return ChainHead.empty(genesisHash);
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
