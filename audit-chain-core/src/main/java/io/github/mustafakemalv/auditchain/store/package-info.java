/**
 * Storage SPI and dependency-free implementations: the append-only {@code AuditStore} contract, an
 * in-memory store, and the reversible details codec. Storage backends that need a third-party
 * library live in a sub-package (for example {@code store.jdbc}) so this package stays free of
 * dependencies.
 */
package io.github.mustafakemalv.auditchain.store;
