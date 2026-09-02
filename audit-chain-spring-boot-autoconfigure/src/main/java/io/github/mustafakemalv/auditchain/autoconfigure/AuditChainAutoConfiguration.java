package io.github.mustafakemalv.auditchain.autoconfigure;

import io.github.mustafakemalv.auditchain.AuditChain;
import io.github.mustafakemalv.auditchain.aop.AuditActorProvider;
import io.github.mustafakemalv.auditchain.aop.AuditedAspect;
import io.github.mustafakemalv.auditchain.store.AuditStore;
import io.github.mustafakemalv.auditchain.store.InMemoryAuditStore;
import io.github.mustafakemalv.auditchain.store.jdbc.JdbcAuditStore;
import java.util.Base64;
import javax.sql.DataSource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Auto-configures an {@link AuditChain}. If the application defines no {@link AuditStore}, one is
 * chosen automatically: a {@link JdbcAuditStore} when a {@link DataSource} is present, otherwise an
 * {@link InMemoryAuditStore} (with a warning, since that does not survive a restart). The HMAC key is
 * read from {@code audit-chain.hmac-key} (base64). The whole configuration backs off when
 * {@code audit-chain.enabled=false}.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "audit-chain", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AuditChainProperties.class)
public class AuditChainAutoConfiguration {

    private static final Log log = LogFactory.getLog(AuditChainAutoConfiguration.class);
    private static final int RECOMMENDED_MIN_KEY_LENGTH = 32;

    @Bean
    @ConditionalOnMissingBean(AuditStore.class)
    AuditStore auditStore(AuditChainProperties properties, ObjectProvider<DataSource> dataSource) {
        DataSource resolved = dataSource.getIfAvailable();
        if (resolved != null) {
            return new JdbcAuditStore(new JdbcTemplate(resolved), properties.getTableName());
        }
        log.warn("audit-chain: no DataSource found, falling back to an in-memory store. Records will "
                + "NOT survive a restart; configure a DataSource for durable auditing.");
        return new InMemoryAuditStore();
    }

    @Bean
    @ConditionalOnMissingBean
    AuditChain auditChain(AuditChainProperties properties, AuditStore auditStore) {
        return new AuditChain(decodeKey(properties.getHmacKey()), auditStore);
    }

    @Bean
    @ConditionalOnMissingBean
    AuditActorProvider auditActorProvider() {
        return () -> "system";
    }

    @Bean
    @ConditionalOnMissingBean
    AuditedAspect auditedAspect(AuditChain auditChain, AuditActorProvider actorProvider) {
        return new AuditedAspect(auditChain, actorProvider);
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
