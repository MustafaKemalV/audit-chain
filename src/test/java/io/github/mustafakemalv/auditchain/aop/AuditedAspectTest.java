package io.github.mustafakemalv.auditchain.aop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.mustafakemalv.auditchain.autoconfigure.AuditChainAutoConfiguration;
import io.github.mustafakemalv.auditchain.core.AuditRecord;
import io.github.mustafakemalv.auditchain.store.AuditStore;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

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
}
