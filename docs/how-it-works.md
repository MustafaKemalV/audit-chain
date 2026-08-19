# How it works

audit-chain turns an append-only log into a **hash chain**: each record carries a hash computed from
its own content and the previous record's hash. Change any past record and its hash no longer
matches, and every record after it is affected too. Because the hash is keyed (HMAC), nobody without
the key can forge a matching hash.

## 1. The record

A caller supplies an `AuditEvent` (actor, action, resourceType, resourceId, details). The chain adds
a `sequence` number and a `timestamp`, producing an `AuditRecord`. That record is the content that
gets hashed.

## 2. Canonical encoding

The hash is computed over bytes, so the same record must always produce the **same** bytes, on any
JVM and after a database round-trip. JSON cannot guarantee that (whitespace, field order, number
formatting, Unicode normalization all vary), so `CanonicalEncoder` uses a binary, **length-prefixed**
format instead:

- Fixed field order: `sequence` (8 bytes), `timestamp` (epoch-second 8 bytes + nanos 4 bytes), then
  `actor`, `action`, `resourceType`, `resourceId`, then `details`.
- Every string is written as its **length** followed by its UTF-8 bytes. A `null` field is written
  as length `-1`, which is distinct from the empty string (length `0`).
- `details` is written as an entry count followed by **sorted** key/value pairs, so map iteration
  order never changes the result.

Length-prefixing removes any delimiter, so no field can bleed into its neighbour. For example
`actor="alice", action="delete"` and `actor="alicedelete", action=""` would collide under naive
concatenation, but encode to different bytes here.

To keep the encoding deterministic across a database round-trip, `append` truncates the timestamp to
milliseconds and the JDBC store persists it as `epoch millis` in a `BIGINT` column.

## 3. The hash chain

For each record:

```
message = lengthPrefixed(canonicalBytes(record)) ‖ lengthPrefixed(previousHash)
hash    = HMAC-SHA256(key, message)
```

The genesis (first) record links to `GENESIS_PREVIOUS_HASH` (32 zero bytes as hex). Length-prefixing
the two parts of `message` keeps the boundary between the record and the previous hash explicit, so
the construction stays injective without relying on the hash being a fixed width.

## 4. Verification

`verify()` walks the chain from sequence 0, tracking the expected sequence number and previous hash.
For each record it checks, in order:

1. `SEQUENCE_GAP` — the sequence number is not the one expected (a record was removed or reordered).
2. `BROKEN_LINK` — `previousHash` does not equal the prior record's hash.
3. `HASH_MISMATCH` — recomputing the hash does not match the stored one (the content was altered).

It returns the **first** broken sequence and the reason, or `intact()`. Comparisons use a
constant-time check so timing cannot leak the key.

An attacker without the key cannot repair the chain: altering a record changes its hash (avalanche
effect), and they cannot compute the correct replacement hash without the key.

## 5. Checkpoints and external anchoring

`head()` returns a `Checkpoint` (sequence + hash) for the current end of the chain. Anchoring that
checkpoint in a separate trust domain closes the one gap the chain alone cannot: an attacker who
holds the key can rewrite the whole log so that `verify()` passes again, but the rewritten hash will
no longer match the checkpoint you anchored elsewhere. `verifyAgainstCheckpoint(anchor)` runs the
internal verification and then compares the anchored hash, reporting `CHECKPOINT_MISMATCH` if the
record at that sequence no longer matches.
