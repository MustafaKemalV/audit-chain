package io.github.mustafakemalv.auditchain.aop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.mustafakemalv.auditchain.autoconfigure.AuditChainAutoConfiguration;
import io.github.mustafakemalv.auditchain.core.AuditRecord;
import io.github.mustafakemalv.auditchain.core.ChainedRecord;
import io.github.mustafakemalv.auditchain.store.AuditStore;
import io.github.mustafakemalv.auditchain.store.AuditStore.RecordSealer;
import io.github.mustafakemalv.auditchain.store.AuditStoreException;
import io.github.mustafakemalv.auditchain.store.InMemoryAuditStore;
import javax.sql.DataSource;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import io.github.mustafakemalv.auditchain.store.jdbc.JdbcAuditStore;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.interceptor.TransactionAspectSupport;

class AuditedAspectTest {

    private static final String KEY_B64 = Base64.getEncoder().encodeToString(new byte[32]);

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AuditChainAutoConfiguration.class))
            .withUserConfiguration(TestConfig.class)
            .withPropertyValues("audit-chain.hmac-key=" + KEY_B64);

    @Test
    void auditedMethodAppendsRecordWithResolvedFields() {
        runner.run(context -> {
            context.getBean(AuditedService.class).deleteUser("42");

            AuditRecord record = context.getBean(AuditStore.class).findAll().get(0).record();
            assertThat(record.action()).isEqualTo("user.delete");
            assertThat(record.resourceType()).isEqualTo("user");
            assertThat(record.resourceId()).isEqualTo("42");
            assertThat(record.actor()).isEqualTo("system");
        });
    }

    @Test
    void methodThatThrowsIsNotRecorded() {
        runner.run(context -> {
            AuditedService service = context.getBean(AuditedService.class);
            assertThatThrownBy(service::failing).isInstanceOf(RuntimeException.class);
            assertThat(context.getBean(AuditStore.class).count()).isZero();
        });
    }

    @Test
    void usesCustomActorProvider() {
        runner.withUserConfiguration(CustomActorConfig.class).run(context -> {
            context.getBean(AuditedService.class).deleteUser("7");
            assertThat(context.getBean(AuditStore.class).findAll().get(0).record().actor()).isEqualTo("alice");
        });
    }

    static class AuditedService {
        @Audited(action = "user.delete", resourceType = "user", resourceId = "#id")
        public void deleteUser(String id) {
            // business logic would go here
        }

        @Audited(action = "thing.fail")
        public void failing() {
            throw new RuntimeException("boom");
        }

        @Audited(action = "thing.sneaky", resourceId = "T(java.lang.System).getProperty('user.name')")
        public void sneaky(String id) {
            // the expression above must not be allowed to evaluate
        }
    }

    @Configuration
    @EnableAspectJAutoProxy(proxyTargetClass = true)
    static class TestConfig {
        @Bean
        AuditedService auditedService() {
            return new AuditedService();
        }
    }

    @Configuration
    static class CustomActorConfig {
        @Bean
        AuditActorProvider actorProvider() {
            return () -> "alice";
        }
    }

    @Test
    void aRecordIsWrittenWhenTheBusinessTransactionCommits() {
        transactionalRunner().run(context -> {
            context.getBean(TransactionalService.class).transferAndCommit("acct-1");

            assertThat(context.getBean(AuditStore.class).count()).isEqualTo(1L);
        });
    }

    @Test
    void aRolledBackTransactionLeavesNoRecord() {
        // The audit entry and the business data commit together or not at all. A log that says an
        // action happened when the transaction rolled back is lying, and a lie is worse than a gap.
        transactionalRunner().run(context -> {
            context.getBean(TransactionalService.class).transferThenRollback("acct-2");

            assertThat(context.getBean(AuditStore.class).count())
                    .as("the method returned normally, but its transaction did not commit")
                    .isZero();
        });
    }

    @Test
    void withoutATransactionTheRecordIsWrittenImmediately() {
        transactionalRunner().run(context -> {
            context.getBean(AuditedService.class).deleteUser("42");

            assertThat(context.getBean(AuditStore.class).count()).isEqualTo(1L);
        });
    }

    @Test
    void anAuditFailureTakesTheBusinessCallDownByDefault() {
        runner.withUserConfiguration(BrokenStoreConfig.class).run(context -> {
            assertThatThrownBy(() -> context.getBean(AuditedService.class).deleteUser("42"))
                    .isInstanceOf(AuditStoreException.class);
        });
    }

    @Test
    void onFailureLogLetsTheBusinessCallSucceedUnrecorded() {
        runner.withUserConfiguration(BrokenStoreConfig.class)
                .withPropertyValues("audit-chain.on-failure=log")
                .run(context -> {
                    // does not throw: the caller chose availability over a complete log
                    context.getBean(AuditedService.class).deleteUser("42");
                });
    }

    @Test
    void expressionsCannotReachBeyondTheMethodArguments() {
        // The expression is a literal from the caller's own source, so this is not injection. The
        // point is that an annotation on a service method has no business reading system properties.
        runner.run(context -> assertThatThrownBy(
                () -> context.getBean(AuditedService.class).sneaky("x"))
                .as("a read-only binding context refuses to resolve types at all")
                .hasMessageContaining("Type cannot be found"));
    }

    private ApplicationContextRunner transactionalRunner() {
        return runner.withUserConfiguration(TransactionalTestConfig.class);
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAspectJAutoProxy
    @EnableTransactionManagement
    static class TransactionalTestConfig {

        @Bean
        DataSource dataSource() {
            return new EmbeddedDatabaseBuilder()
                    .setType(EmbeddedDatabaseType.H2)
                    .generateUniqueName(true)
                    .addScript("classpath:audit-chain/schema.sql")
                    .build();
        }

        @Bean
        PlatformTransactionManager transactionManager(DataSource dataSource) {
            return new DataSourceTransactionManager(dataSource);
        }

        @Bean
        JdbcTemplate jdbcTemplate(DataSource dataSource) {
            return new JdbcTemplate(dataSource);
        }

        @Bean
        TransactionalService transactionalService() {
            return new TransactionalService();
        }

        @Bean
        ReadOnlyService readOnlyService() {
            return new ReadOnlyService();
        }

        @Bean
        InnerService innerService() {
            return new InnerService();
        }

        @Bean
        NestedService nestedService(InnerService inner) {
            return new NestedService(inner);
        }
    }

    static class TransactionalService {

        @Transactional
        @Audited(action = "money.transfer", resourceType = "account", resourceId = "#id")
        public void transferAndCommit(String id) {
            // business work that commits
        }

        @Transactional
        @Audited(action = "money.transfer", resourceType = "account", resourceId = "#id")
        public void transferThenRollback(String id) {
            // returns normally, but the transaction is doomed
            TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class BrokenStoreConfig {

        @Bean
        CountingService countingService() {
            return new CountingService();
        }

        @Bean
        AuditStore auditStore() {
            return new InMemoryAuditStore() {
                @Override
                public synchronized ChainedRecord appendSealed(RecordSealer sealer) {
                    throw new AuditStoreException("the database is on fire");
                }
            };
        }
    }

    @Test
    void aReadOnlyTransactionStillRecordsTheRead() {
        // Auditing a read ("who viewed this record") is a normal requirement, and a read-only
        // transaction cannot carry the write: the database refuses both the row lock and the insert.
        // The write therefore goes into a transaction of its own, which costs nothing here because a
        // read has no fate for the record to share.
        transactionalRunner().withUserConfiguration(RecordingStoreConfig.class).run(context -> {
            context.getBean(ReadOnlyService.class).view("42");

            RecordingStore store = context.getBean(RecordingStore.class);
            assertThat(store.count()).isEqualTo(1L);
            assertThat(store.independentWrites).as("written outside the read-only transaction").isEqualTo(1);
        });
    }

    @Test
    void aRolledBackSavepointLeavesNoRecord() {
        // The audit write joins the caller's transaction, so it is subject to savepoints like any
        // other write. An earlier version deferred the write to beforeCommit, which is not scoped to
        // savepoints, so work that had been rolled back was still recorded as having happened.
        transactionalRunner().run(context -> {
            context.getBean(NestedService.class).outerThatRollsBackItsInnerWork();

            assertThat(context.getBean(AuditStore.class).count())
                    .as("the inner work was undone, so nothing should attest to it")
                    .isZero();
        });
    }

    @Test
    void logModeKeepsTheBusinessWorkWhenTheAuditWriteFails() {
        // Swallowing the exception is not enough on its own: a failure inside the caller's
        // transaction marks it rollback-only, so the business work would be lost anyway and the log
        // line claiming the action succeeded would be false.
        runner.withUserConfiguration(BrokenStoreConfig.class)
                .withPropertyValues("audit-chain.on-failure=log")
                .run(context -> {
                    CountingService service = context.getBean(CountingService.class);
                    service.doWork();

                    assertThat(service.isCompleted()).as("the business call ran to completion").isTrue();
                });
    }

    @Configuration(proxyBeanMethods = false)
    static class RecordingStoreConfig {

        @Bean
        RecordingStore auditStore(JdbcTemplate jdbcTemplate, PlatformTransactionManager transactionManager) {
            return new RecordingStore(jdbcTemplate, transactionManager);
        }
    }

    /** Counts which write path the chain took, so the test can assert the transaction decision. */
    static class RecordingStore extends JdbcAuditStore {

        int independentWrites;

        RecordingStore(JdbcTemplate jdbcTemplate, PlatformTransactionManager transactionManager) {
            super(jdbcTemplate, "audit_chain", JdbcAuditStore.DEFAULT_HEAD_TABLE, transactionManager);
        }

        @Override
        public ChainedRecord appendSealedIndependently(RecordSealer sealer) {
            independentWrites++;
            return super.appendSealedIndependently(sealer);
        }
    }

    static class ReadOnlyService {

        @Transactional(readOnly = true)
        @Audited(action = "record.viewed", resourceType = "user", resourceId = "#id")
        public void view(String id) {
            // a read that still has to be recorded
        }
    }

    static class NestedService {

        private final InnerService inner;

        NestedService(InnerService inner) {
            this.inner = inner;
        }

        @Transactional
        public void outerThatRollsBackItsInnerWork() {
            try {
                inner.auditedThenRollBack();
            } catch (RuntimeException ignored) {
                // the savepoint rollback is the point of the test
            }
        }
    }

    static class InnerService {

        @Transactional(propagation = Propagation.NESTED)
        @Audited(action = "nested.op")
        public void auditedThenRollBack() {
            TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
        }
    }

    static class CountingService {

        private boolean completed;

        @Transactional
        @Audited(action = "counted.op")
        public void doWork() {
            completed = true;
        }

        /** Read through a method: a CGLIB proxy does not expose the target's fields. */
        public boolean isCompleted() {
            return completed;
        }
    }
}
