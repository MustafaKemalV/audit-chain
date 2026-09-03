package io.github.mustafakemalv.auditchain.autoconfigure;

import io.github.mustafakemalv.auditchain.AuditChain;
import io.github.mustafakemalv.auditchain.aop.AuditActorProvider;
import io.github.mustafakemalv.auditchain.aop.AuditFailureMode;
import io.github.mustafakemalv.auditchain.aop.AuditedAspect;
import io.github.mustafakemalv.auditchain.store.AuditStore;
import io.github.mustafakemalv.auditchain.store.InMemoryAuditStore;
import io.github.mustafakemalv.auditchain.store.jdbc.JdbcAuditStore;
import java.util.Base64;
import javax.sql.DataSource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * Auto-configures an {@link AuditChain}. If the application defines no {@link AuditStore}, one is
 * chosen automatically: a {@link JdbcAuditStore} when a {@link DataSource} is present, otherwise an
 * {@link InMemoryAuditStore} (with a warning, since that does not survive a restart). The HMAC key is
 * read from {@code audit-chain.hmac-key} (base64), and the chain identity from
 * {@code audit-chain.chain-id}, which defaults to the table name. The whole configuration backs off
 * when {@code audit-chain.enabled=false}.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "audit-chain", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AuditChainProperties.class)
public class AuditChainAutoConfiguration {

    private static final Log log = LogFactory.getLog(AuditChainAutoConfiguration.class);
    private static final int RECOMMENDED_MIN_KEY_LENGTH = 32;

    @Bean
    @ConditionalOnMissingBean(AuditStore.class)
    AuditStore auditStore(AuditChainProperties properties, ObjectProvider<DataSource> dataSources,
            ObjectProvider<PlatformTransactionManager> transactionManagers, BeanFactory beanFactory) {
        DataSource resolved = resolveDataSource(properties, dataSources, beanFactory);
        if (resolved != null) {
            // The application's own transaction manager, not one built here from the DataSource.
            // Spring joins an existing transaction only through the manager that started it, so
            // constructing our own would silently open a second transaction under JTA, JPA without a
            // DataSource, or a proxy-wrapped one, and the audit record would then outlive a rolled
            // back business operation.
            PlatformTransactionManager transactionManager = transactionManagers.getIfUnique();
            if (transactionManager == null && transactionManagers.stream().findAny().isPresent()) {
                log.warn("audit-chain: several PlatformTransactionManager beans are defined and none "
                        + "is marked @Primary, so audit writes will manage their own transactions and "
                        + "may not share the fate of the business operation they record.");
            }
            return new JdbcAuditStore(new JdbcTemplate(resolved), properties.getTableName(),
                    JdbcAuditStore.DEFAULT_HEAD_TABLE, transactionManager);
        }
        log.warn("audit-chain: no DataSource found, falling back to an in-memory store. Records will "
                + "NOT survive a restart; configure a DataSource for durable auditing.");
        return new InMemoryAuditStore();
    }

    private static DataSource resolveDataSource(AuditChainProperties properties,
            ObjectProvider<DataSource> dataSources, BeanFactory beanFactory) {
        String configured = properties.getDatasourceBeanName();
        if (configured != null && !configured.isBlank()) {
            return beanFactory.getBean(configured.strip(), DataSource.class);
        }
        DataSource unique = dataSources.getIfUnique();
        if (unique != null) {
            return unique;
        }
        if (dataSources.stream().findAny().isPresent()) {
            // Several candidates and no instruction. Falling back to the in-memory store here would
            // start the application with an audit log that quietly does not survive a restart, which
            // is worse than not starting at all.
            throw new IllegalStateException("audit-chain: several DataSource beans are defined and none "
                    + "is marked @Primary, so it is not clear which one holds the audit table. Set "
                    + "audit-chain.datasource-bean-name to choose one.");
        }
        return null;
    }

    @Bean
    @ConditionalOnMissingBean
    AuditChain auditChain(AuditChainProperties properties, AuditStore auditStore) {
        return new AuditChain(decodeKey(properties.getHmacKey()), auditStore, properties.resolveChainId());
    }

    @Bean
    @ConditionalOnMissingBean
    AuditActorProvider auditActorProvider() {
        return () -> "system";
    }

    @Bean
    @ConditionalOnMissingBean
    AuditedAspect auditedAspect(AuditChain auditChain, AuditActorProvider actorProvider,
            AuditChainProperties properties) {
        return new AuditedAspect(auditChain, actorProvider, properties.getOnFailure());
    }

    private static byte[] decodeKey(String hmacKey) {
        if (hmacKey == null || hmacKey.isBlank()) {
            throw new IllegalStateException(
                    "audit-chain.hmac-key must be set (base64-encoded) when audit-chain is enabled");
        }
        byte[] key;
        try {
            key = Base64.getDecoder().decode(hmacKey.strip());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("audit-chain.hmac-key must be valid base64", e);
        }
        if (key.length < RECOMMENDED_MIN_KEY_LENGTH) {
            log.warn("audit-chain: hmac-key is only " + key.length + " bytes; at least "
                    + RECOMMENDED_MIN_KEY_LENGTH + " bytes is recommended for HMAC-SHA256.");
        }
        return key;
    }
}
