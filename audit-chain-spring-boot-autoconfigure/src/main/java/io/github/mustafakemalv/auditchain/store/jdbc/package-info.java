/**
 * JDBC-backed {@code AuditStore}. Kept in its own package so the dependency-free
 * {@code store} package and this Spring-dependent one never share a package across two artifacts.
 */
package io.github.mustafakemalv.auditchain.store.jdbc;
