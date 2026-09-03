package io.github.mustafakemalv.auditchain.autoconfigure;

import io.github.mustafakemalv.auditchain.AuditChain;
import io.github.mustafakemalv.auditchain.aop.AuditFailureMode;
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
     * key. Defaults to {@code default}, the same value the plain constructor uses, so a chain
     * written while prototyping still verifies once the starter takes over. Set it explicitly, and
     * differently, whenever one key covers more than one log; never reuse an id across logs.
     */
    private String chainId;

    /**
     * Which DataSource bean the JDBC store should use. Only needed when the application defines more
     * than one; with a single DataSource it is picked up automatically.
     */
    private String datasourceBeanName;

    /**
     * What an {@code @Audited} method does when the audit write itself fails: FAIL lets the failure
     * reach the caller and take the business operation with it, LOG records the problem and lets the
     * operation succeed unrecorded. FAIL is the default because an audit log with silent holes is
     * hard to trust.
     */
    private AuditFailureMode onFailure = AuditFailureMode.FAIL;

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

    public AuditFailureMode getOnFailure() {
        return onFailure;
    }

    public void setOnFailure(AuditFailureMode onFailure) {
        this.onFailure = onFailure;
    }

    public String getDatasourceBeanName() {
        return datasourceBeanName;
    }

    public void setDatasourceBeanName(String datasourceBeanName) {
        this.datasourceBeanName = datasourceBeanName;
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
        // Deliberately not the table name. Defaulting to it kept two tables apart for free, but it
        // also meant the library had two different defaults, and the chain id is inside the hash: a
        // chain written with the plain constructor reported HASH_MISMATCH on every record once the
        // same application moved to the starter, with no migration path.
        //
        // strip() is not applied either. This value exists to keep identities apart, so quietly
        // folding "tenant-a" and " tenant-a " into one identity would defeat it; an id that differs
        // only by whitespace is a different id, and one that is only whitespace is a mistake.
        return chainId == null || chainId.isEmpty() ? AuditChain.DEFAULT_CHAIN_ID : chainId;
    }
}
