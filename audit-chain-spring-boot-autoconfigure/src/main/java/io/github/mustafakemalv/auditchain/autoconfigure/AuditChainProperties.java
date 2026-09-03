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
     * key. Defaults to the table name, so a second audit table is a second chain without anyone
     * configuring it, and the default table name equals {@link AuditChain#DEFAULT_CHAIN_ID} so a
     * chain written with the plain constructor still verifies once the starter takes over. Never
     * reuse an id across two logs.
     */
    private String chainId;

    /**
     * Which DataSource bean the JDBC store should use. Only needed when the application defines more
     * than one; with a single DataSource it is picked up automatically.
     */
    private String datasourceBeanName;

    /**
     * Which PlatformTransactionManager bean governs the audit table. Only needed when the
     * application defines more than one; with a single manager it is picked up automatically.
     */
    private String transactionManagerBeanName;

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

    public String getTransactionManagerBeanName() {
        return transactionManagerBeanName;
    }

    public void setTransactionManagerBeanName(String transactionManagerBeanName) {
        this.transactionManagerBeanName = transactionManagerBeanName;
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
        // The table name, so two audit tables under one key are two identities without anyone
        // configuring it. Losing that default once let a tenant's history be replaced wholesale with
        // another tenant's, verifying clean, because both resolved to the same id. The default table
        // name is deliberately equal to AuditChain.DEFAULT_CHAIN_ID, so the plain constructor and
        // the starter agree and a chain written while prototyping keeps verifying.
        //
        // No trimming: this value exists to keep identities apart, so folding two spellings into one
        // would defeat it.
        return chainId == null || chainId.isEmpty() ? tableName : chainId;
    }
}
