# audit-chain

[![CI](https://github.com/MustafaKemalV/audit-chain/actions/workflows/ci.yml/badge.svg)](https://github.com/MustafaKemalV/audit-chain/actions/workflows/ci.yml)

A Spring Boot starter for a **tamper-evident, append-only audit log**. Each record is hash-chained
to the previous one with HMAC-SHA256, so any change to a past entry breaks the chain and `verify()`
pinpoints exactly where it broke.

## Features

- **Hash-chained records:** `hash(n) = HMAC-SHA256(key, canonicalBytes(record) ‖ previousHash)`.
- **`verify()` locates the break** and says why: content changed (`HASH_MISMATCH`), link broken
  (`BROKEN_LINK`), or a record removed/reordered (`SEQUENCE_GAP`).
- **Deterministic canonical encoding** (binary, length-prefixed, never JSON), so the same record
  always hashes identically across machines and database round-trips.
- **Two ways to record:** an imperative `AuditChain.append(...)` service and a declarative
  `@Audited` annotation.
- **Pluggable `AuditStore` SPI:** append-only JDBC store and an in-memory store, or bring your own.
- **External anchoring hook:** export a `Checkpoint` and later `verifyAgainstCheckpoint(...)` to
  catch even a stolen-key rewrite.

## Requirements

- Java 25
- Spring Boot 4.1

## Installation

Not yet published to Maven Central. Build and install it into your local Maven repository:

```bash
git clone https://github.com/MustafaKemalV/audit-chain.git
cd audit-chain
mvn install
```

Then add the dependency:

```xml
<dependency>
    <groupId>io.github.mustafakemalv</groupId>
    <artifactId>audit-chain-spring-boot-starter</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

## Quick start

### 1. Configure the key

The HMAC key is base64-encoded. Generate a strong one (32 bytes minimum for HMAC-SHA256):

```bash
openssl rand -base64 32
```

```yaml
audit-chain:
  hmac-key: ${AUDIT_CHAIN_HMAC_KEY}   # keep the key in a secret / env var, NOT in the repo
  table-name: audit_chain             # optional, this is the default
```

Keep the key out of version control and, ideally, out of the database's blast radius (a KMS/secret
manager). If no key is set, the application fails fast at startup.

### 2. Create the table

With a `DataSource` present, audit-chain uses a JDBC append-only store. Create the table from
[`schema.sql`](src/main/resources/audit-chain/schema.sql) (via Flyway/Liquibase or by hand). To make
append-only a real guarantee, grant the audit DB role `INSERT` and `SELECT` but **not** `UPDATE` or
`DELETE`. Without a `DataSource`, audit-chain falls back to an in-memory store (dev only; it logs a
warning and does not survive a restart).

### 3. Record events

Imperative, for full control over what is logged:

```java
@Service
class UserService {

    private final AuditChain auditChain;

    UserService(AuditChain auditChain) {
        this.auditChain = auditChain;
    }

    void deleteUser(String actor, String userId) {
        // ... business logic ...
        auditChain.append(new AuditEvent(
                actor, "user.delete", "user", userId, Map.of("via", "admin-console")));
    }
}
```

Declarative, for simple method-level auditing (AOP support is included):

```java
@Audited(action = "user.delete", resourceType = "user", resourceId = "#userId")
public void deleteUser(String userId) {
    // audited automatically after a successful return
}
```

The recorded `actor` comes from an `AuditActorProvider` bean (defaults to `"system"`). Provide your
own so the actor is the **server-verified** identity, never client-supplied input:

```java
@Bean
AuditActorProvider auditActorProvider(/* your security context */) {
    return () -> SecurityContextHolder.getContext().getAuthentication().getName();
}
```

### 4. Verify

```java
VerificationResult result = auditChain.verify();
if (!result.valid()) {
    log.error("Audit chain broken at sequence {}: {}", result.brokenSequence(), result.reason());
}
```

### 5. Anchor a checkpoint (optional, strongest guarantee)

```java
Checkpoint anchor = auditChain.head().orElseThrow();
// write `anchor` to a separate trust domain: another service, a transparency log, cold storage...

// later, this catches even a rewrite made with a stolen key:
VerificationResult result = auditChain.verifyAgainstCheckpoint(anchor);
```

## How it works

See [docs/how-it-works.md](docs/how-it-works.md) for the canonical encoding, the hash chain, and how
`verify()` pinpoints tampering.

## Threat model (honest scope)

audit-chain is tamper-**evident**, not tamper-**proof**. It detects tampering by anyone who does
**not** hold the HMAC key. It does **not** stop an attacker who holds the key or can rewrite the
whole log consistently (HMAC is symmetric: whoever can verify can also sign). It also does not
verify *who* an actor is; deriving the correct `actor` is your authentication layer's job. For
defence beyond keyless tamper-evidence, the library gives you hooks, not guarantees:

- export the chain head to an **external anchor** (a separate trust domain / transparency log) and
  check it with `verifyAgainstCheckpoint(...)`,
- run the store on **WORM / INSERT-only** storage (grant `INSERT`, revoke `UPDATE`/`DELETE`),
- keep the HMAC key in a **KMS/HSM**, separate from the database.

## Limitations

- **Single writer:** `append` is synchronized, which is correct for one JVM. A distributed
  deployment needs sequence coordination at the storage layer; the `sequence` primary key turns a
  race into a failed insert rather than silent corruption.
- **`verify()` reads the whole chain** into memory. For very large logs, verify in batches (planned).
- **The chain starts at sequence 0** and is a single monotonic run; log rotation/archival is not
  supported yet.

## License

MIT License, Copyright (c) 2026 Mustafa Kemal Vural. See [LICENSE](LICENSE).
