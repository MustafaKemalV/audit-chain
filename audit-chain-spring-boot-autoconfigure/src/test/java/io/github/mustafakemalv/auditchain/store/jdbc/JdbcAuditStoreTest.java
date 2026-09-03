package io.github.mustafakemalv.auditchain.store.jdbc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.mustafakemalv.auditchain.AuditChain;
import io.github.mustafakemalv.auditchain.core.AuditEvent;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import io.github.mustafakemalv.auditchain.core.Checkpoint;
import io.github.mustafakemalv.auditchain.core.FailureReason;
import io.github.mustafakemalv.auditchain.core.VerificationResult;
import io.github.mustafakemalv.auditchain.store.AuditStore;
import io.github.mustafakemalv.auditchain.store.AuditStoreException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.LongStream;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import javax.sql.DataSource;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.jdbc.core.RowMapper;
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
        // Handing back a record that ignores the tip stands in for any way that could happen.
        AuditChain chain = newChain();
        ChainedRecord first = chain.append(AuditEvent.of("alice", "login"));

        assertThatThrownBy(() -> store.appendSealed(head -> first))
                .isInstanceOf(AuditStoreException.class);
        assertThat(store.count()).isEqualTo(1L);
    }

    @Test
    void deletingTheNewestRowsIsDetected() {
        // Straight SQL, bypassing the library entirely, the way an attacker with DELETE would do it.
        // What is left is a valid shorter chain, so only the remembered length reveals the deletion.
        AuditChain chain = newChain();
        for (int i = 0; i < 5; i++) {
            chain.append(AuditEvent.of("alice", "act." + i));
        }
        assertThat(chain.verify().valid()).isTrue();

        jdbcTemplate.update("DELETE FROM audit_chain WHERE sequence >= 3");

        VerificationResult result = chain.verify();
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.TRUNCATED);
        assertThat(result.brokenSequence()).isEqualTo(3L);
    }

    @Test
    void deletingEveryRowIsDetected() {
        AuditChain chain = newChain();
        for (int i = 0; i < 3; i++) {
            chain.append(AuditEvent.of("alice", "act." + i));
        }

        jdbcTemplate.update("DELETE FROM audit_chain");

        VerificationResult result = chain.verify();
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.TRUNCATED);
    }

    @Test
    void aCorruptDetailsColumnIsReportedRatherThanThrown() {
        // The scenario the library exists for: someone altered a row. Verification must answer
        // "broken here", not propagate a decoding error from a JDK utility class, or a monitoring
        // job that calls verify() on a schedule crashes instead of alerting.
        AuditChain chain = newChain();
        chain.append(AuditEvent.of("alice", "login"));
        chain.append(new AuditEvent("bob", "delete", "doc", "2", Map.of("reason", "cleanup")));

        jdbcTemplate.update("UPDATE audit_chain SET details = 'not-base64!!!' WHERE sequence = 1");

        VerificationResult result = chain.verify();
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.UNREADABLE_RECORD);
        assertThat(result.brokenSequence()).isEqualTo(1L);
    }

    @Test
    void concurrentAppendsFromTwoChainsLoseNothing() throws Exception {
        // Two application instances writing to one database. This used to drop about half the
        // records while verify() still reported the chain intact, which is the worst combination
        // available to an audit log: missing evidence and a clean bill of health.
        AuditChain node1 = newChain();
        AuditChain node2 = newChain();
        int total = 60;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < total; i++) {
            AuditChain node = (i % 2 == 0) ? node1 : node2;
            futures.add(pool.submit(() -> {
                start.await();
                return node.append(AuditEvent.of("user", "payment.approve"));
            }));
        }
        start.countDown();
        int stored = 0;
        for (Future<?> future : futures) {
            try {
                future.get(30, TimeUnit.SECONDS);
                stored++;
            } catch (ExecutionException e) {
                // counted as a loss below
            }
        }
        pool.shutdownNow();

        assertThat(stored).as("every append must be recorded").isEqualTo(total);
        assertThat(store.count()).isEqualTo(total);
        assertThat(newChain().verify().valid()).isTrue();
        assertThat(store.findAll().stream().map(r -> r.record().sequence()).toList())
                .isEqualTo(LongStream.range(0, total).boxed().toList());
    }

    @Test
    void rejectsOversizedStringsBeforeTheDatabaseCanTruncateThem() {
        // The guard that already existed for details, applied to the columns it was missing from.
        // On a non-strict database an over-long actor is silently cut down, the row stops re-hashing
        // to its stored hash, and the chain reports as tampered with forever.
        AuditChain chain = newChain();
        String tooLong = "a".repeat(256);

        assertThatThrownBy(() -> chain.append(AuditEvent.of(tooLong, "login")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("actor");
        assertThatThrownBy(() -> chain.append(AuditEvent.of("alice", tooLong)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("action");
        assertThatThrownBy(() -> chain.append(AuditEvent.of("alice", "login", tooLong, "1")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("resourceType");
        assertThatThrownBy(() -> chain.append(AuditEvent.of("alice", "login", "user", tooLong)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("resourceId");

        assertThat(store.count()).as("nothing was written").isZero();
    }

    @Test
    void acceptsStringsExactlyAtTheColumnLimit() {
        AuditChain chain = newChain();
        String atLimit = "a".repeat(255);

        chain.append(AuditEvent.of(atLimit, "login", atLimit, atLimit));

        assertThat(chain.verify().valid()).isTrue();
    }

    @Test
    void twoAppendsInOneTransactionDoNotDeadlock() throws Exception {
        // The shape the README's own example produces: two audited calls in one business
        // transaction, with another request auditing at the same time. A chain-level monitor plus a
        // database row lock had opposite lifetimes here, the monitor released on return and the row
        // lock held until commit, so the two threads waited on each other. The JVM's deadlock
        // detector cannot see it either, because half the cycle lives in the database.
        TransactionTemplate tx = new TransactionTemplate(new DataSourceTransactionManager(database));
        AuditChain chain = newChain();
        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch firstAppendDone = new CountDownLatch(1);

        Future<?> holder = pool.submit(() -> tx.executeWithoutResult(status -> {
            chain.append(AuditEvent.of("t1", "first"));
            firstAppendDone.countDown();
            sleepBriefly();
            chain.append(AuditEvent.of("t1", "second"));
        }));
        assertThat(firstAppendDone.await(10, TimeUnit.SECONDS)).isTrue();
        Future<?> other = pool.submit(() -> tx.executeWithoutResult(status ->
                chain.append(AuditEvent.of("t2", "concurrent"))));

        try {
            holder.get(20, TimeUnit.SECONDS);
            other.get(20, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            throw new AssertionError("appends deadlocked: neither transaction finished", e);
        } finally {
            pool.shutdownNow();
        }

        assertThat(store.count()).isEqualTo(3L);
        assertThat(chain.verify().valid()).isTrue();
    }

    private static void sleepBriefly() {
        try {
            Thread.sleep(300);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Test
    void deletingTheTipRowIsReportedRatherThanHidingTheDeletion() {
        // Removing the tip row used to disable the truncation check silently, so deleting it along
        // with the records produced a clean bill of health. Records with no tip is never a fresh
        // chain, and the two sources contradicting each other is free to detect.
        AuditChain chain = newChain();
        for (int i = 0; i < 5; i++) {
            chain.append(AuditEvent.of("alice", "act." + i));
        }
        jdbcTemplate.update("DELETE FROM audit_chain WHERE sequence >= 3");
        assertThat(chain.verify().reason()).isEqualTo(FailureReason.TRUNCATED);

        jdbcTemplate.update("DELETE FROM audit_chain_head");

        VerificationResult result = chain.verify();
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(FailureReason.CHAIN_HEAD_MISMATCH);
        assertThat(store.count()).as("the records are still there").isEqualTo(3L);
    }

    @Test
    void theExportedCheckpointComesFromARecordNotFromTheTipRow() {
        // Anchoring what the tip claims would let anyone who can write to it choose what gets
        // anchored: set the tip back, let the anchoring job export that, then delete everything
        // above it, and both verifications pass.
        AuditChain chain = newChain();
        for (int i = 0; i < 10; i++) {
            chain.append(AuditEvent.of("alice", "act." + i));
        }
        Checkpoint honest = chain.head().orElseThrow();

        String hashOfThree = jdbcTemplate
                .queryForObject("SELECT hash FROM audit_chain WHERE sequence = 3", String.class).trim();
        jdbcTemplate.update("UPDATE audit_chain_head SET last_sequence = 3, last_hash = ?,"
                + " record_count = 4 WHERE chain_table = 'audit_chain'", hashOfThree);

        assertThat(chain.head().orElseThrow().sequence())
                .as("the tip row cannot choose the anchor")
                .isEqualTo(honest.sequence());
    }

    @Test
    void aChainWithACustomTableNameDoesNotRaceOnItsFirstAppends() throws Exception {
        // The shipped schema seeds a tip row for the default table name only, so any other chain
        // starts without one, and a lock on a row that is not there takes nothing. The store now
        // creates the row itself, in a transaction of its own so two writers cannot both try inside
        // their own uncommitted append.
        jdbcTemplate.execute("CREATE TABLE my_audit AS SELECT * FROM audit_chain WHERE 1 = 0");
        jdbcTemplate.update("DELETE FROM audit_chain_head");
        int total = 40;

        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < total; i++) {
            AuditChain node = new AuditChain(KEY,
                    new JdbcAuditStore(jdbcTemplate, "my_audit", JdbcAuditStore.DEFAULT_HEAD_TABLE,
                            new DataSourceTransactionManager(database)),
                    "my_audit");
            futures.add(pool.submit(() -> node.append(AuditEvent.of("user", "act"))));
        }
        start.countDown();
        int stored = 0;
        for (Future<?> future : futures) {
            try {
                future.get(30, TimeUnit.SECONDS);
                stored++;
            } catch (ExecutionException e) {
                // counted as a loss
            }
        }
        pool.shutdownNow();

        assertThat(stored).as("no append may be lost on a freshly created chain").isEqualTo(total);
        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM my_audit", Long.class))
                .isEqualTo(total);
    }

    @Test
    void verifyReturnsAVerdictForAnyContentTheTablesCanHold() {
        // The docs call verification total: for any bytes the tables happen to hold it returns a
        // result rather than throwing. A monitoring job that calls verify() on a schedule has to get
        // an answer even when the answer is produced by content nobody expected, otherwise tampering
        // surfaces as a crash instead of an alert. Every value below is legal for its column type,
        // and two of them are writable with exactly the privileges the README recommends granting.
        record Corruption(String description, String sql) { }
        List<Corruption> corruptions = List.of(
                new Corruption("details is not base64",
                        "UPDATE audit_chain SET details = 'not-base64!!!' WHERE sequence = 1"),
                new Corruption("details decodes to a map with a null key",
                        "UPDATE audit_chain SET details = 'AAAAAf////8AAAAA' WHERE sequence = 1"),
                new Corruption("format_version is zero",
                        "UPDATE audit_chain SET format_version = 0 WHERE sequence = 1"),
                new Corruption("format_version is negative",
                        "UPDATE audit_chain SET format_version = -3 WHERE sequence = 1"),
                new Corruption("previous_hash is not a hash",
                        "UPDATE audit_chain SET previous_hash = 'zzz' WHERE sequence = 1"),
                new Corruption("the tip remembers a negative count",
                        "UPDATE audit_chain_head SET record_count = -1"),
                new Corruption("the tip's sequence is below the genesis",
                        "UPDATE audit_chain_head SET last_sequence = -2"),
                new Corruption("the tip's hash is not a hash",
                        "UPDATE audit_chain_head SET last_hash = 'zzz'"));

        for (Corruption corruption : corruptions) {
            resetChainWithThreeRecords();
            jdbcTemplate.update(corruption.sql());

            VerificationResult result = catchVerdict();

            assertThat(result)
                    .as("verify() threw instead of reporting: %s", corruption.description())
                    .isNotNull();
            assertThat(result.valid())
                    .as("corrupted content must not verify: %s", corruption.description())
                    .isFalse();
        }
    }

    /** Runs verify() and returns null if it threw, so the assertion can name what broke. */
    private VerificationResult catchVerdict() {
        try {
            return newChain().verify();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private void resetChainWithThreeRecords() {
        jdbcTemplate.update("DELETE FROM audit_chain");
        jdbcTemplate.update("DELETE FROM audit_chain_head");
        AuditChain chain = newChain();
        for (int i = 0; i < 3; i++) {
            chain.append(AuditEvent.of("alice", "act." + i));
        }
    }

    @Test
    void anUnreadableRecordIsFoundWithoutScanningEveryRow() {
        // Locating the bad record used to cost a query per record, so corrupting one cell near the
        // end of a page amplified every future verification a thousandfold. It also has to name the
        // right record, which is what makes the result actionable.
        AuditChain chain = newChain();
        for (int i = 0; i < 300; i++) {
            chain.append(AuditEvent.of("alice", "act." + i));
        }
        jdbcTemplate.update("UPDATE audit_chain SET details = 'not-base64!!!' WHERE sequence = 250");

        CountingJdbcTemplate counting = new CountingJdbcTemplate(database);
        AuditChain counted = new AuditChain(KEY,
                new JdbcAuditStore(counting, "audit_chain", JdbcAuditStore.DEFAULT_HEAD_TABLE,
                        new DataSourceTransactionManager(database)),
                "audit_chain");

        VerificationResult result = counted.verify();

        assertThat(result.reason()).isEqualTo(FailureReason.UNREADABLE_RECORD);
        assertThat(result.brokenSequence()).isEqualTo(250L);
        assertThat(counting.queries)
                .as("narrowing by halving, not one query per record")
                .isLessThan(30);
    }

    /** Counts the queries a verification costs, so amplification is measured rather than assumed. */
    static class CountingJdbcTemplate extends JdbcTemplate {

        int queries;

        CountingJdbcTemplate(DataSource dataSource) {
            super(dataSource);
        }

        @Override
        public <T> List<T> query(PreparedStatementCreator psc, RowMapper<T> rowMapper) {
            queries++;
            return super.query(psc, rowMapper);
        }
    }
}
