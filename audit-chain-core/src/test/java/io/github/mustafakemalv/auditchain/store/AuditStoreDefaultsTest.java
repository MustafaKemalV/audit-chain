package io.github.mustafakemalv.auditchain.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.mustafakemalv.auditchain.AuditChain;
import io.github.mustafakemalv.auditchain.core.AuditEvent;
import io.github.mustafakemalv.auditchain.core.ChainHead;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.LongStream;
import org.junit.jupiter.api.Test;

/**
 * Exercises the SPI through a store written the way a third party would write one: from the javadoc,
 * implementing only what the interface requires.
 *
 * <p>This class exists because an earlier shape of the SPI let such a store lose records silently.
 * {@code appendSealed} was a default that read the tip and wrote in two steps, and {@code lockHead}
 * was a default whose name promised a lock it did not take, so a correct-looking implementation
 * dropped 95 of 200 concurrent appends while {@code verify()} still reported the chain intact. The
 * interface now asks for sealing as one atomic step, which is not something an implementer can
 * provide by accident, and these tests hold that line.
 */
class AuditStoreDefaultsTest {

    private static final byte[] KEY = "an-audit-hmac-key".getBytes(StandardCharsets.UTF_8);

    /**
     * Everything the interface requires, and nothing more. The append is exclusive because the SPI
     * says it has to be; that is the whole contract an implementer has to get right.
     */
    private static final class MinimalStore implements AuditStore {

        private final List<ChainedRecord> records = new ArrayList<>();
        private long everStored;

        @Override
        public synchronized ChainedRecord appendSealed(RecordSealer sealer) {
            ChainedRecord sealed = sealer.seal(head());
            if (!records.isEmpty()
                    && sealed.record().sequence() <= records.get(records.size() - 1).record().sequence()) {
                throw new AuditStoreException("duplicate sequence");
            }
            records.add(sealed);
            everStored++;
            return sealed;
        }

        @Override
        public synchronized ChainHead head() {
            if (records.isEmpty()) {
                return ChainHead.emptyWithHistory(everStored);
            }
            ChainedRecord last = records.get(records.size() - 1);
            return new ChainHead(last.record().sequence(), last.hash(), everStored);
        }

        @Override
        public synchronized List<ChainedRecord> findRange(long fromSequence, int limit) {
            if (limit <= 0) {
                throw new IllegalArgumentException("limit must be positive");
            }
            List<ChainedRecord> slice = new ArrayList<>();
            for (ChainedRecord record : records) {
                if (record.record().sequence() >= fromSequence) {
                    slice.add(record);
                    if (slice.size() == limit) {
                        break;
                    }
                }
            }
            return slice;
        }

        @Override
        public synchronized long count() {
            return records.size();
        }

        synchronized void dropNewest(int howMany) {
            for (int i = 0; i < howMany && !records.isEmpty(); i++) {
                records.remove(records.size() - 1);
            }
        }
    }

    @Test
    void aStoreWithOnlyTheRequiredMethodsWorksAsAChain() {
        MinimalStore store = new MinimalStore();
        AuditChain chain = new AuditChain(KEY, store);

        chain.append(AuditEvent.of("alice", "login"));
        chain.append(AuditEvent.of("bob", "logout"));

        assertThat(chain.verify().valid()).isTrue();
        assertThat(store.count()).isEqualTo(2L);
    }

    @Test
    void aMinimalStoreLosesNothingUnderConcurrentAppends() {
        // The regression this class was written for. Two chains over one store is two application
        // instances; the old SPI lost roughly half the records here and still reported INTACT.
        MinimalStore store = new MinimalStore();
        AuditChain node1 = new AuditChain(KEY, store, "shared");
        AuditChain node2 = new AuditChain(KEY, store, "shared");
        int total = 120;

        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(total);
        AtomicInteger lost = new AtomicInteger();
        for (int i = 0; i < total; i++) {
            AuditChain node = (i % 2 == 0) ? node1 : node2;
            pool.submit(() -> {
                try {
                    start.await();
                    node.append(AuditEvent.of("user", "payment.approve"));
                } catch (Exception e) {
                    lost.incrementAndGet();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        try {
            assertThat(done.await(60, TimeUnit.SECONDS)).isTrue();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(e);
        }
        pool.shutdownNow();

        assertThat(lost.get()).as("no append may be lost").isZero();
        assertThat(store.count()).isEqualTo(total);
        assertThat(node1.verify().valid()).isTrue();
        assertThat(store.findAll().stream().map(r -> r.record().sequence()).toList())
                .isEqualTo(LongStream.range(0, total).boxed().toList());
    }

    @Test
    void aMinimalStoreKeepingAHighWaterMarkStillSeesTruncation() {
        // The SPI asks for a count that outlives the records. A store that honours it gets truncation
        // detection for free, without any of the JDBC store's machinery.
        MinimalStore store = new MinimalStore();
        AuditChain chain = new AuditChain(KEY, store);
        for (int i = 0; i < 5; i++) {
            chain.append(AuditEvent.of("alice", "act." + i));
        }
        assertThat(chain.verify().valid()).isTrue();

        store.dropNewest(2);

        assertThat(chain.verify().valid()).isFalse();
        assertThat(chain.verify().reason())
                .isEqualTo(io.github.mustafakemalv.auditchain.core.FailureReason.TRUNCATED);
    }

    @Test
    void lastIsDerivedFromTheTipAndAgreesWithIt() {
        MinimalStore store = new MinimalStore();
        assertThat(store.last()).isEmpty();

        AuditChain chain = new AuditChain(KEY, store);
        chain.append(AuditEvent.of("alice", "login"));
        ChainedRecord second = chain.append(AuditEvent.of("bob", "logout"));

        assertThat(store.last()).contains(second);
        assertThat(store.last().orElseThrow().hash()).isEqualTo(store.head().lastHash());
    }

    @Test
    void findAllIsDerivedByPagingAndRejectsANonPositiveLimit() {
        MinimalStore store = new MinimalStore();
        AuditChain chain = new AuditChain(KEY, store);
        for (int i = 0; i < 7; i++) {
            chain.append(AuditEvent.of("alice", "act." + i));
        }

        assertThat(store.findAll()).hasSize(7);
        assertThat(store.findRange(3L, 2).stream().map(r -> r.record().sequence()).toList())
                .containsExactly(3L, 4L);
        assertThatThrownBy(() -> store.findRange(0L, 0)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void anEmptyStoreReportsAnEmptyTip() {
        MinimalStore store = new MinimalStore();

        assertThat(store.head()).isEqualTo(ChainHead.empty());
        assertThat(store.head().isEmpty()).isTrue();
        assertThat(store.head().nextSequence()).isZero();
    }
}
