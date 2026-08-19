package io.github.mustafakemalv.auditchain.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Binds {@code audit-chain.*} configuration. */
@ConfigurationProperties(prefix = "audit-chain")
public class AuditChainProperties {

    /** Whether audit-chain auto-configuration is active. */
    private boolean enabled = true;

    /** Base64-encoded HMAC-SHA256 key used to seal the chain. Required when enabled. */
    private String hmacKey;

    /** Name of the append-only table used by the JDBC store. */
    private String tableName = "audit_chain";

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getHmacKey() {
        return hmacKey;
    }

    public void setHmacKey(String hmacKey) {
        this.hmacKey = hmacKey;
    }

    public String getTableName() {
        return tableName;
    }

    public void setTableName(String tableName) {
        this.tableName = tableName;
    }
}
