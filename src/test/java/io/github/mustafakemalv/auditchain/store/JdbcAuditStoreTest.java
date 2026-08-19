package io.github.mustafakemalv.auditchain.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.mustafakemalv.auditchain.AuditChain;
import io.github.mustafakemalv.auditchain.core.AuditEvent;
import io.github.mustafakemalv.auditchain.core.FailureReason;
import io.github.mustafakemalv.auditchain.core.VerificationResult;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;

class JdbcAuditStoreTest {

    private static final byte[] KEY = "an-audit-hmac-key".getBytes(StandardCharsets.UTF_8);

    private EmbeddedDatabase database;
    private JdbcTemplate jdbcTemplate;
    private JdbcAuditStore store;

    @BeforeEach
    void setUp() {
        database = new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript("classpath:audit-chain/schema.sql")
                .build();
        jdbcTemplate = new JdbcTemplate(database);
        store = new JdbcAuditStore(jdbcTemplate, "audit_chain");
    }

    @AfterEach
    void tearDown() {
        database.shutdown();
    }

    private AuditChain newChain() {
        return new AuditChain(KEY, store);
    }

    @Test
    void rejectsUnsafeTableName() {
        assertThatThrownBy(() -> new JdbcAuditStore(jdbcTemplate, "audit; DROP TABLE users"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void appendsAndVerifiesAcrossTheDatabase() {
        AuditChain chain = newChain();
        chain.append(AuditEvent.of("alice", "login", "user", "1"));
        chain.append(new AuditEvent("bob", "delete", "doc", "2", Map.of("reason", "cleanup")));
        chain.append(AuditEvent.of("carol", "update", "doc", "3"));

        assertThat(store.count()).isEqualTo(3);
        assertThat(chain.verify().valid()).isTrue();
    }

    @Test
    void columnsRoundTripThroughAFreshChain() {
        newChain().append(new AuditEvent("bob", "delete", "doc", "2",
                Map.of("reason", "cleanup", "ip", "1.2.3.4")));

        // a brand-new chain reading the stored rows must still verify: proves timestamp and details
        // survive the trip through the columns unchanged
        assertThat(new AuditChain(KEY, store).verify().valid()).isTrue();
    }

    @Test
    void detectsDirectSqlUpdateTampering() {
        AuditChain chain = newChain();
        chain.append(AuditEvent.of("alice", "login", "user", "1"));
        chain.append(new AuditEvent("bob", "delete", "doc", "2", Map.of("reason", "cleanup")));
        chain.append(AuditEvent.of("carol", "update", "doc", "3"));

        // bare SQL straight into the table, bypassing the library entirely
        jdbcTemplate.update("UPDATE audit_chain SET actor = 'attacker' WHERE sequence = 1");

        VerificationResult result = chain.verify();
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.HASH_MISMATCH);
        assertThat(result.brokenSequence()).isEqualTo(1L);
    }

    @Test
    void detectsDeletedRowAsSequenceGap() {
        AuditChain chain = newChain();
        chain.append(AuditEvent.of("alice", "login"));
        chain.append(AuditEvent.of("bob", "logout"));
        chain.append(AuditEvent.of("carol", "login"));

        jdbcTemplate.update("DELETE FROM audit_chain WHERE sequence = 1");

        VerificationResult result = chain.verify();
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.SEQUENCE_GAP);
        assertThat(result.brokenSequence()).isEqualTo(2L);
    }
}
