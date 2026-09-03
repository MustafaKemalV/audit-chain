# audit-chain

[![CI](https://github.com/MustafaKemalV/audit-chain/actions/workflows/ci.yml/badge.svg)](https://github.com/MustafaKemalV/audit-chain/actions/workflows/ci.yml)

A Spring Boot starter for a **tamper-evident, append-only audit log**. Each record is hash-chained
to the previous one with HMAC-SHA256, so any change to a past entry breaks the chain and `verify()`
pinpoints exactly where it broke.

## Features

- **Hash-chained records:**
  `hash(n) = HMAC-SHA256(key, domainTag ‖ chainId ‖ canonicalBytes(record) ‖ previousHash)`, with
  every part length-prefixed so no combination can be re-split into a different one.
- **`verify()` locates the break** and says why: content altered (`HASH_MISMATCH`), link rewritten
  or records reordered (`BROKEN_LINK`), record removed from the start or middle (`SEQUENCE_GAP`),
  records deleted from the end (`TRUNCATED`), a row that no longer decodes (`UNREADABLE_RECORD`), or
  a chain whose stored tip is gone (`CHAIN_HEAD_MISMATCH`). It never throws: any content the tables
  can hold produces a verdict, because a scheduled check has to alert rather than crash.
- **Appends do not race.** Writers from several application instances serialize on the chain's head
  row, so no audit record is lost to a concurrent write.
- **Deterministic canonical encoding** (binary, length-prefixed, never JSON), so the same record
  always hashes identically across machines and database round-trips.
- **Two ways to record:** an imperative `AuditChain.append(...)` service and a declarative
  `@Audited` annotation.
- **Pluggable `AuditStore` SPI:** append-only JDBC store and an in-memory store, or bring your own.
- **External anchoring hook:** export a `Checkpoint` and later `verifyAgainstCheckpoint(...)` to
  catch even a stolen-key rewrite.
- **Usable without Spring:** the chain itself lives in `audit-chain-core`, which has no compile
  dependencies at all. The Spring Boot wiring sits in separate artifacts on top of it.

## Requirements

- **Java 25.** This is a deliberate choice, not a technical necessity: the sources compile on 17.
  It means consumers on JDK 17 or 21 cannot use these artifacts, and Spring Boot 4.1 itself
  baselines on 17, so this library is stricter than the framework it targets.
- **Spring Boot 4.1**, for the starter and the auto-configuration only. `audit-chain-core` needs
  neither Spring nor a database.

## Modules

| Artifact | What it gives you | Dependencies |
| --- | --- | --- |
| `audit-chain-core` | The hash chain, canonical encoding, the `AuditStore` SPI and an in-memory store | none |
| `audit-chain-spring-boot-autoconfigure` | The JDBC store, the `@Audited` aspect, the properties | core, Spring, AspectJ |
| `audit-chain-spring-boot-starter` | Everything wired up for a Boot application | the autoconfigure module |

Use the starter in a Spring Boot application. Reach for `audit-chain-core` on its own when you want
the chain in plain Java, or in a framework other than Spring, and intend to write your own
`AuditStore`.

## Installation

Not yet published to Maven Central. Build and install it into your local Maven repository:

```bash
git clone https://github.com/MustafaKemalV/audit-chain.git
cd audit-chain
mvn install
```

Then add the starter:

```xml
<dependency>
    <groupId>io.github.mustafakemalv</groupId>
    <artifactId>audit-chain-spring-boot-starter</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

Or, for the chain alone with no Spring on the classpath:

```xml
<dependency>
    <groupId>io.github.mustafakemalv</groupId>
    <artifactId>audit-chain-core</artifactId>
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

With a `DataSource` present, audit-chain uses a JDBC append-only store. Create the tables from
[`schema.sql`](audit-chain-spring-boot-autoconfigure/src/main/resources/audit-chain/schema.sql)
(via Flyway/Liquibase or by hand). There are two: `audit_chain` holds the records, and
`audit_chain_head` holds one row per chain, which is where appends serialize and where the chain's
length is remembered. The script also seeds that row, which matters: a row lock can only order
writers if there is a row to lock.

They need different privileges, and the difference is what makes truncation detectable. See
[Database privileges](#database-privileges).

Without a `DataSource`, audit-chain falls back to an in-memory store (dev only; it logs a warning
and does not survive a restart). If the application defines several `DataSource` beans and none is
`@Primary`, startup fails with a message telling you to set `audit-chain.datasource-bean-name`,
rather than quietly auditing into memory.

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

## Configuration

| Property | Default | What it does |
| --- | --- | --- |
| `audit-chain.enabled` | `true` | Turns the whole auto-configuration off |
| `audit-chain.hmac-key` | none | Base64 HMAC key. Required; startup fails without it |
| `audit-chain.table-name` | `audit_chain` | The append-only table |
| `audit-chain.chain-id` | `default` | Bound into every hash, so records cannot be moved between chains sealed with the same key |
| `audit-chain.datasource-bean-name` | none | Which `DataSource` holds the audit table. Only needed when there is more than one |
| `audit-chain.on-failure` | `FAIL` | What an `@Audited` method does when the audit write fails. `FAIL` writes in the caller's transaction, so the record and the business data commit together and a failure takes the call down with it. `LOG` writes in a transaction of its own, so the call survives an audit failure and the record survives a business rollback: availability bought with atomicity |

**On `chain-id`:** give each log its own whenever one key covers more than one of them. There is a
single default, `default`, shared by the starter and the plain constructor, so a chain written while
prototyping keeps verifying once the starter takes over. The value is taken exactly as given and
goes into every hash: reusing an id across two logs re-opens the hole it exists to close, and
changing it makes the existing history unverifiable, with no migration path.

## How it works

See [docs/how-it-works.md](docs/how-it-works.md) for the canonical encoding, the hash chain, and how
`verify()` pinpoints tampering.

## Threat model (honest scope)

audit-chain is tamper-**evident**, not tamper-**proof**. It does not prevent anyone from changing
the database; it makes the change show up when the log is verified.

### What `verify()` catches

Each of these is covered by a test, and the reason it reports is the one named here.

| Tampering | Reported as |
| --- | --- |
| A record's content was edited | `HASH_MISMATCH` |
| A record was forged and appended | `HASH_MISMATCH`, or `BROKEN_LINK` if its link is wrong too |
| A record was removed from the start or the middle | `SEQUENCE_GAP` |
| Records were reordered | `BROKEN_LINK`, or `HASH_MISMATCH` if their contents were swapped |
| A link was rewritten to point elsewhere | `BROKEN_LINK` |
| Records were deleted from the **end**, or the whole log was wiped | `TRUNCATED` |
| Records from **another chain** were moved in, under the same key | `HASH_MISMATCH` |
| A row's stored bytes will no longer decode | `UNREADABLE_RECORD` |
| The stored tip is gone while records remain | `CHAIN_HEAD_MISMATCH` |

Reordering is worth a note, because the obvious guess is wrong. Swapping two sequence numbers does
not produce a `SEQUENCE_GAP`: the store returns rows in sequence order, so the numbers still run
0, 1, 2 and it is the links between them that no longer line up.

The last four rows are worth spelling out, because a plain hash chain catches none of them.

**Deleting from the end** leaves a shorter but perfectly valid chain, so the hash links cannot see
it. It is caught by `audit_chain_head`, which remembers how many records the chain has ever held.
**That protection is worth exactly as much as the grants on that table**: whoever can write there
can lower the count and hide the deletion. See [Database privileges](#database-privileges).

**Removing the tip row** does not disable that check: records with no tip at all is never a fresh
chain, so it is reported rather than believed. What it cannot do is tell you what the tip used to
say, so the chain's length is no longer provable from that point on.

**Moving records between chains** is caught because `chain-id` is bound into every hash. Without it,
a genuine and correctly signed history from one log verifies perfectly inside another log sealed
with the same key, so an incriminating trail could be replaced wholesale with someone else's, no key
required.

**A row that will not decode** is reported rather than thrown, so a monitoring job that calls
`verify()` on a schedule alerts instead of crashing.

### What it does not catch

- **An attacker who holds the HMAC key** can rewrite the log consistently and it will verify. HMAC
  is symmetric: whoever can verify can also sign. The one thing that still catches this is a
  `Checkpoint` anchored somewhere the attacker does not control, checked with
  `verifyAgainstCheckpoint(...)`.
- **An attacker who can also write to `audit_chain_head`** can hide a deletion from the end of the
  chain, by lowering the remembered count to match what is left.
- **An action that was never recorded.** The log can only attest to what reached it. If the audit
  write is skipped, or the code path has no `append` in it, there is nothing to detect.
- **Whether the actor is who they claim to be.** Deriving a correct `actor` is your authentication
  layer's job; this library records what it is given.
- **Anything above the anchor, with a stolen key.** A checkpoint pins the chain up to its own
  sequence. A rewrite of records after it still verifies, so anchor often if that matters.

### Hardening beyond the defaults

- Anchor the chain head somewhere in a **separate trust domain** and check it with
  `verifyAgainstCheckpoint(...)`.
- Run the audit table on **WORM / INSERT-only** storage.
- Keep the HMAC key in a **KMS/HSM**, out of the database's blast radius.
- Give `audit_chain_head` its own grants, as below.

## Database privileges

The two tables need different privileges, and the difference is the point.

```sql
GRANT INSERT, SELECT         ON audit_chain      TO audit_app;
GRANT INSERT, SELECT, UPDATE ON audit_chain_head TO audit_app;
```

`audit_chain` is append-only and never needs `UPDATE` or `DELETE`. `audit_chain_head` holds one row
per chain and does need `UPDATE`, because that row is both where appends serialize and where the
chain's length is remembered.

Someone who can write to the head row can stall appends and can hide a truncation, but cannot forge
a record: the hashes still have to line up. Someone who can write to `audit_chain` but not to the
head row cannot delete the newest records without it showing.

## Limitations

- **A chain is serial by nature.** A record cannot be sealed until the one before it is settled, so
  appends to one chain are processed one at a time. This is a property of hash chains, not an
  implementation shortcut. Throughput scales by running **several chains**, each with its own
  `chain-id` and table: appends serialize on a chain's own tip row, so separate chains do not wait
  for each other. How much that buys you depends on your database and your transaction sizes, so
  measure it on your own setup rather than trusting a number measured on someone else's.
- **`verify()` reads the whole chain**, in pages rather than all at once, but it still walks every
  record from the start. It is O(n) in the length of the log, and there is no incremental
  verification from a trusted point yet.
- **The chain starts at sequence 0** and is a single monotonic run. Log rotation and archival are
  not supported.
- **`@Audited` writes inside the caller's transaction**, as the method returns, so a rolled-back
  transaction leaves no record and work rolled back to a savepoint leaves none either. This is
  deliberate: an audit entry saying an action happened when the transaction rolled back is a lie,
  and a lie is worse than a gap. Whether the aspect runs inside the transaction is decided by advice
  ordering and cannot be forced from the library, though in practice the transaction interceptor is
  the outer one; if it matters to you, assert it, because an audit write that fails should take the
  business call down with it.
- **A read-only transaction still records.** It cannot carry the write, since the database refuses
  both the row lock and the insert, so the record goes into a transaction of its own. It could not
  share a read's fate in any case.
- **To record attempts that were rolled back**, call `auditChain.appendIndependently(...)`, which
  writes in its own transaction and so neither rolls back with the caller's work nor can fail it.
  `@Audited` also records no `details`; use `append(...)` for contextual key/values.
- **Only proxied calls are audited.** A call from inside the same bean, and `private`, `final` or
  `static` methods, are not recorded. This is the usual Spring proxying caveat.
- **`@Audited` expressions need `-parameters`.** Without it `#id` resolves to `null` and every
  record loses its resource id. The library logs a warning once per method when it detects this;
  Spring Boot's own parent POM enables the flag.
- **Column limits are enforced before insert.** `details` must fit 4000 characters encoded, and
  `actor`, `action`, `resourceType` and `resourceId` must fit 255. Oversized values are rejected
  rather than left to a database that would silently truncate them, because a truncated value no
  longer re-hashes to its stored hash and would report as tampering forever.
- **Empty strings on Oracle.** A database that treats `''` as `NULL` will round-trip an empty field
  as `null` and fail verification. Use a database that distinguishes them, or avoid empty-string
  fields.

## License

MIT License, Copyright (c) 2026 Mustafa Kemal Vural. See [LICENSE](LICENSE).
