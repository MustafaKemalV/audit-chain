package io.github.mustafakemalv.auditchain.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.mustafakemalv.auditchain.AuditChain;
import io.github.mustafakemalv.auditchain.store.AuditStore;
import io.github.mustafakemalv.auditchain.store.InMemoryAuditStore;
import io.github.mustafakemalv.auditchain.store.jdbc.JdbcAuditStore;
import java.util.Base64;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;

class AuditChainAutoConfigurationTest {

    private static final String KEY_B64 = Base64.getEncoder().encodeToString(new byte[32]);

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AuditChainAutoConfiguration.class));

    @Test
    void createsChainWithJdbcStoreWhenDataSourcePresent() {
        runner.withUserConfiguration(DataSourceConfig.class)
                .withPropertyValues("audit-chain.hmac-key=" + KEY_B64)
                .run(context -> {
                    assertThat(context).hasSingleBean(AuditChain.class);
                    assertThat(context).getBean(AuditStore.class).isInstanceOf(JdbcAuditStore.class);
                });
    }

    @Test
    void fallsBackToInMemoryStoreWithoutDataSource() {
        runner.withPropertyValues("audit-chain.hmac-key=" + KEY_B64)
                .run(context -> {
                    assertThat(context).hasSingleBean(AuditChain.class);
                    assertThat(context).getBean(AuditStore.class).isInstanceOf(InMemoryAuditStore.class);
                });
    }

    @Test
    void backsOffWhenUserDefinesOwnStore() {
        runner.withUserConfiguration(DataSourceConfig.class, CustomStoreConfig.class)
                .withPropertyValues("audit-chain.hmac-key=" + KEY_B64)
                .run(context ->
                        // DataSource is present, but the user's own store wins over the auto JDBC store
                        assertThat(context).getBean(AuditStore.class).isInstanceOf(InMemoryAuditStore.class));
    }

    @Test
    void failsWhenKeyMissing() {
        runner.run(context -> assertThat(context).hasFailed());
    }

    @Test
    void backsOffEntirelyWhenDisabled() {
        runner.withPropertyValues("audit-chain.enabled=false", "audit-chain.hmac-key=" + KEY_B64)
                .run(context -> assertThat(context).doesNotHaveBean(AuditChain.class));
    }

    @Configuration
    static class DataSourceConfig {
        @Bean
        DataSource dataSource() {
            return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2).build();
        }
    }

    @Configuration
    static class CustomStoreConfig {
        @Bean
        AuditStore auditStore() {
            return new InMemoryAuditStore();
        }
    }
}
