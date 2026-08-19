package io.github.mustafakemalv.auditchain.store;

import io.github.mustafakemalv.auditchain.core.AuditRecord;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

/**
 * JDBC-backed {@link AuditStore} that appends each record as one row via {@link JdbcTemplate}. The
 * table is treated as append-only: this class only ever INSERTs and SELECTs. To make that a real
 * guarantee, grant the audit database role INSERT and SELECT but not UPDATE or DELETE.
 *
 * <p>The timestamp is stored as epoch milliseconds so it round-trips exactly (the chain truncates
 * timestamps to milliseconds when appending), and the details map is stored in one column via
 * {@link DetailsCodec}.
 */
public class JdbcAuditStore implements AuditStore {

    private static final Pattern SAFE_TABLE_NAME = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]*$");

    private static final RowMapper<ChainedRecord> ROW_MAPPER = (rs, rowNum) -> {
        AuditRecord record = new AuditRecord(
                rs.getLong("sequence"),
                Instant.ofEpochMilli(rs.getLong("timestamp_ms")),
                rs.getString("actor"),
                rs.getString("action"),
                rs.getString("resource_type"),
                rs.getString("resource_id"),
                DetailsCodec.decode(rs.getString("details")));
        return new ChainedRecord(record, rs.getString("previous_hash"), rs.getString("hash"));
    };

    private final JdbcTemplate jdbcTemplate;
    private final String tableName;

    public JdbcAuditStore(JdbcTemplate jdbcTemplate, String tableName) {
        if (jdbcTemplate == null) {
            throw new IllegalArgumentException("jdbcTemplate is required");
        }
        // The table name cannot be a bind parameter, so it is concatenated into the SQL. Validate it
        // strictly to keep that concatenation safe from injection.
        if (tableName == null || !SAFE_TABLE_NAME.matcher(tableName).matches()) {
            throw new IllegalArgumentException("tableName must match " + SAFE_TABLE_NAME.pattern());
        }
        this.jdbcTemplate = jdbcTemplate;
        this.tableName = tableName;
    }

    @Override
    public void append(ChainedRecord record) {
        AuditRecord r = record.record();
        jdbcTemplate.update(
                "INSERT INTO " + tableName + " (sequence, timestamp_ms, actor, action, resource_type,"
                        + " resource_id, details, previous_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                r.sequence(),
                r.timestamp().toEpochMilli(),
                r.actor(),
                r.action(),
                r.resourceType(),
                r.resourceId(),
                DetailsCodec.encode(r.details()),
                record.previousHash(),
                record.hash());
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
        }
    }

    @Override
    public List<ChainedRecord> findAll() {
        return jdbcTemplate.query("SELECT * FROM " + tableName + " ORDER BY sequence ASC", ROW_MAPPER);
    }

    @Override
    public long count() {
        Long count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM " + tableName, Long.class);
        return count == null ? 0L : count;
    }
}
