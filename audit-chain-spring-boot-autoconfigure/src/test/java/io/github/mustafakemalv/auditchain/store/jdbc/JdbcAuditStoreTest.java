package io.github.mustafakemalv.auditchain.store.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.mustafakemalv.auditchain.AuditChain;
import io.github.mustafakemalv.auditchain.core.AuditEvent;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import io.github.mustafakemalv.auditchain.core.FailureReason;
import io.github.mustafakemalv.auditchain.core.VerificationResult;
import io.github.mustafakemalv.auditchain.store.AuditStore;
import io.github.mustafakemalv.auditchain.store.AuditStoreException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.LongStream;
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

    @Test
    void rejectsOversizedDetails() {
        String big = "x".repeat(5000);
        AuditChain chain = newChain();
        assertThatThrownBy(() ->
                chain.append(new AuditEvent("a", "act", null, null, Map.of("blob", big))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void findRangeReturnsASliceInSequenceOrder() {
        AuditChain chain = newChain();
        for (int i = 0; i < 10; i++) {
            chain.append(AuditEvent.of("alice", "act." + i));
        }

        List<ChainedRecord> slice = store.findRange(3L, 4);

        assertThat(slice).hasSize(4);
        assertThat(slice.stream().map(r -> r.record().sequence()).toList())
                .containsExactly(3L, 4L, 5L, 6L);
    }

    @Test
    void findRangeStopsAtTheEndOfTheChain() {
        AuditChain chain = newChain();
        chain.append(AuditEvent.of("alice", "only"));

        assertThat(store.findRange(0L, 100)).hasSize(1);
        assertThat(store.findRange(5L, 100)).isEmpty();
    }

    @Test
    void findRangeWalksTheWholeChainInBatches() {
        // This is the batched verification path the SPI exists to allow: read a page, remember the
        // next sequence, read the next page, never holding the whole log at once.
        AuditChain chain = newChain();
        for (int i = 0; i < 25; i++) {
            chain.append(AuditEvent.of("alice", "act." + i));
        }

        List<Long> walked = new ArrayList<>();
        long from = 0L;
        while (true) {
            List<ChainedRecord> page = store.findRange(from, 7);
            if (page.isEmpty()) {
                break;
            }
            page.forEach(r -> walked.add(r.record().sequence()));
            from = page.get(page.size() - 1).record().sequence() + 1;
        }

        assertThat(walked).hasSize(25);
        assertThat(walked).isEqualTo(LongStream.range(0, 25).boxed().toList());
    }

    @Test
    void findRangeRejectsANonPositiveLimit() {
        assertThatThrownBy(() -> store.findRange(0L, 0))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aDatabaseFailureSurfacesAsAnAuditStoreException() {
        // The SPI promises callers a single exception type; a caller must not have to catch
        // Spring's DataAccessException to handle a failed audit write.
        AuditChain chain = newChain();
        chain.append(AuditEvent.of("alice", "login"));
        jdbcTemplate.execute("DROP TABLE audit_chain");

        assertThatThrownBy(() -> store.findAll()).isInstanceOf(AuditStoreException.class);
        assertThatThrownBy(() -> store.count()).isInstanceOf(AuditStoreException.class);
        assertThatThrownBy(() -> store.last()).isInstanceOf(AuditStoreException.class);
        assertThatThrownBy(() -> store.findRange(0L, 10)).isInstanceOf(AuditStoreException.class);
    }

    @Test
    void aDuplicateSequenceIsRejectedRatherThanForkingTheChain() {
        // The chain's whole anti-fork guarantee rests on the store refusing a repeated sequence.
        AuditChain chain = newChain();
        ChainedRecord first = chain.append(AuditEvent.of("alice", "login"));

        assertThatThrownBy(() -> store.append(first))
                .isInstanceOf(AuditStoreException.class);
        assertThat(store.count()).isEqualTo(1L);
    }
}
