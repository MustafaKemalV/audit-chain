# audit-chain

A Spring Boot starter for a **tamper-evident, append-only audit log**. Each record is hash-chained
to the previous one with HMAC-SHA256, so any change to a past entry breaks the chain and `verify()`
pinpoints the first record that was tampered with.

> **Status: work in progress.** The public API and docs are still being built.

## What it does

- Append-only audit records, each linked to the previous one:
  `hash(n) = HMAC-SHA256(key, canonicalBytes(record) ‖ hash(n-1))`.
- `verify()` walks the chain, recomputes every hash, and returns the first broken sequence number.
- Deterministic, JSON-independent **canonical encoding**, so the same record always hashes identically.
- Pluggable `AuditStore` SPI (JDBC append-only table + in-memory).

## Threat model (honest scope)

audit-chain is tamper-**evident**, not tamper-**proof**. It detects tampering by anyone who does
**not** hold the HMAC key. It does **not** stop an attacker who holds the key or can rewrite the
whole log consistently (HMAC is symmetric: whoever can verify can also sign). For defence against
that, the library gives you hooks, not guarantees:

- export the chain head to an **external anchor** (a separate trust domain / transparency log),
- run the store on **WORM / INSERT-only** storage (grant the DB role INSERT, revoke UPDATE/DELETE),
- keep the HMAC key in a **KMS/HSM**, separate from the database.

## Requirements

- Java 25
- Spring Boot 4.1

## License

MIT License, Copyright (c) 2026 Mustafa Kemal Vural. See [LICENSE](LICENSE).
