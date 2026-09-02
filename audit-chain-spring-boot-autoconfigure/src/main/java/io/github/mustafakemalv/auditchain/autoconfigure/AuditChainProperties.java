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

    /**
     * Identity bound into every hash, so records cannot be moved between chains sealed with the same
     * key. Defaults to the table name, which keeps two tables under one key apart without any
     * configuration. Set it explicitly when one key covers several logs, and never reuse an id
     * across logs.
     */
    private String chainId;

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

    public String getChainId() {
        return chainId;
    }

    public void setChainId(String chainId) {
        this.chainId = chainId;
    }

    /**
     * The configured chain id, or the table name when none was set.
     *
     * @return the identity to bind into this chain's hashes
     */
    public String resolveChainId() {
        return chainId == null || chainId.isBlank() ? tableName : chainId.strip();
    }
}
