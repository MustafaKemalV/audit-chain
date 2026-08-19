/**
 * Tamper-evident, append-only audit log for Spring Boot.
 * {@link io.github.mustafakemalv.auditchain.AuditChain} hash-chains each record with HMAC-SHA256 and
 * its {@code verify()} pinpoints where the chain broke.
 */
package io.github.mustafakemalv.auditchain;
