# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

Published versions on Maven Central are immutable, so this file is the only record of what changed
between them.

## [0.1.0] - 2026-09-03

First release.

### Added

- Split into three artifacts: `audit-chain-core` (no compile dependencies, usable without Spring),
  `audit-chain-spring-boot-autoconfigure`, and `audit-chain-spring-boot-starter`.
- A format version written as the first field of the canonical encoding and stored with every
  record, so the encoding can change without making existing chains unverifiable.
- A chain identity bound into every hash, so records cannot be moved between chains sealed with the
  same key. Configured with `audit-chain.chain-id`.
- `audit_chain_head`, one row per chain, which serializes appends and remembers how many records the
  chain has ever held. This is what makes deletion from the end of a log detectable.
- `TRUNCATED`, `UNREADABLE_RECORD` and `CHAIN_HEAD_MISMATCH` verification results.
- `AuditChainException` with `AuditStoreException` and `MalformedRecordException`, so a caller can
  handle a failed audit write without catching Spring's exception types.
- `AuditChain.appendIndependently(...)` for recording something whose fate is deliberately separate
  from the caller's transaction, such as an attempt that was rolled back.
- `audit-chain.on-failure`, choosing whether a failed audit write takes the business call down with
  it or is only logged.
- `audit-chain.datasource-bean-name`, for applications with more than one `DataSource`.
- Batched verification through `AuditStore.findRange`, so verifying does not hold an entire log in
  memory.

### Fixed

- Concurrent appends from more than one application instance no longer lose records. Measured
  against PostgreSQL, 45 of 100 appends previously vanished while `verify()` still reported the
  chain intact.
- Deleting records from the end of the log, or the whole log, is now detected.
- `verify()` no longer throws for any content the tables can hold; corrupt rows are reported rather
  than escaping as decoding errors.
- `@Audited` no longer deadlocks when a transaction contains two audited calls.
- The audit write joins the application's own transaction, instead of one the store created for
  itself, which could commit the record separately and let it survive a business rollback.
- `@Audited` works inside a read-only transaction, and leaves no record when work is rolled back to
  a savepoint.
- Oversized `actor`, `action`, `resourceType` and `resourceId` values are rejected before insert,
  rather than being silently truncated by a database and breaking the chain permanently.
- An application defining several `DataSource` beans starts, with a message naming the fix.
- `spring-configuration-metadata.json` ships in the jar again, so IDEs offer completion for
  `audit-chain.*` properties.
