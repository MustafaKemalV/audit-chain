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
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
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
        TransactionalService transactionalService() {
            return new TransactionalService();
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
        AuditStore auditStore() {
            return new InMemoryAuditStore() {
                @Override
                public synchronized ChainedRecord appendSealed(RecordSealer sealer) {
                    throw new AuditStoreException("the database is on fire");
                }
            };
        }
    }
}
