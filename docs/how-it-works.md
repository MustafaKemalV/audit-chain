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

- A **format version** (4 bytes) comes first. See [Format versioning](#6-format-versioning).
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

### Writing a verifier in another language

Two details are easy to get wrong and are not visible from the description above:

- All integers are **big-endian**, which is what Java's `DataOutputStream` writes.
- `details` keys are sorted by Java's natural `String` order, which is **UTF-16 code-unit order**.
  That differs from UTF-8 byte order for supplementary characters, so a verifier that sorts by UTF-8
  bytes will disagree on any map mixing emoji with characters in U+E000 to U+FFFF.

`CanonicalEncoderTest` contains a golden vector: a fixed record and the exact hex its encoding must
produce. It is the most reliable thing to test a reimplementation against.

## 3. The hash chain

For each record:

```
message = lengthPrefixed("audit-chain/v1")
        ‖ lengthPrefixed(chainId)
        ‖ lengthPrefixed(canonicalBytes(record))
        ‖ lengthPrefixed(previousHash)
hash    = HMAC-SHA256(key, message)
```

The genesis (first) record links to `GENESIS_PREVIOUS_HASH` (32 zero bytes as hex). Length-prefixing
every part keeps each boundary explicit, so the construction stays injective without relying on any
part having a fixed width.

The first two parts are what keep chains apart. The **domain tag** separates this construction from
any other use of the same key. The **chain id** ties a record to the log it was written for: without
it, a genuine and correctly signed history from one chain verifies perfectly inside another chain
sealed with the same key, so an incriminating trail could be replaced wholesale with someone else's,
no key required. One key covering several logs is the natural multi-tenant setup, which is exactly
when this matters.

## 4. Verification

`verify()` walks the chain from sequence 0 in pages, tracking the expected sequence number and
previous hash. For each record it checks, in order:

1. `SEQUENCE_GAP`: the sequence number is not the one expected (a record was removed or reordered).
2. `BROKEN_LINK`: `previousHash` does not equal the prior record's hash.
3. `HASH_MISMATCH`: recomputing the hash does not match the stored one (the content was altered).
4. `UNREADABLE_RECORD`: the stored bytes will not decode, or the row claims a format version this
   build cannot write.

After the walk it compares how many records it saw against the chain's remembered length, reporting
`TRUNCATED` if records are missing from the end. This check exists because the hash links cannot
reveal that particular deletion: what is left after it is a shorter but perfectly valid chain.

It returns the **first** broken sequence and the reason, or `intact()`. Comparisons use a
constant-time check.

Verification is **total**: for any content the table happens to hold, it returns a result rather than
throwing. A monitoring job asking "is the log intact" has to get an answer even when the answer is
produced by bytes nobody expected, otherwise tampering shows up as a crash instead of an alert.

An attacker without the key cannot repair the chain: altering a record changes its hash (avalanche
effect), and they cannot compute the correct replacement hash without the key.

## 5. The head row

`audit_chain_head` holds one row per chain, doing two jobs that turn out to be the same job.

**Appends serialize on it.** A hash chain cannot be built in parallel, because a record cannot be
sealed until the one before it is settled. Two writers that read the same tip compute the same
sequence number, and one of them loses its record. Taking a row lock while reading the tip turns
that collision into an orderly queue.

Two things had to be true for that lock to mean anything, and both were learned the hard way. The
lock has to be held across the whole read-then-write step, which is why sealing a record is handed
to the store as one unit of work: outside a transaction the lock is released the moment the read
finishes, and the protection quietly disappears. And there has to be a row to lock, which is why the
schema seeds it.

**It remembers the chain's length.** `record_count` only ever grows, and verification compares it
against the records actually present. That is what makes deleting the newest rows visible.

The cost is that this table needs `UPDATE`, unlike the audit table, so it has to be granted
separately. Whoever can write to it can stall appends and can hide a truncation, but cannot forge a
record: the hashes still have to line up.

A rolled-back transaction leaves no gap. The sequence is derived from committed state on every
append and never from a counter, so a number claimed by a transaction that then rolled back is
simply claimed again by the next one.

## 6. Format versioning

The canonical encoding writes its version as the first field, and each stored record carries the
version its hash was computed under.

Without this the encoding could never change. Adding a field or reordering one would silently
produce different bytes for the same record, every hash already stored would stop matching, and
nothing would tell a reader whether a given row used the old layout or the new one. With it, records
keep their own version and stay verifiable after the format moves on.

A record claiming a version this build cannot write is reported as `UNREADABLE_RECORD` rather than
hashed under a guessed layout, because a guess would produce a mismatch and read as tampering that
never happened.

## 7. Checkpoints and external anchoring

`head()` returns a `Checkpoint` (sequence + hash) for the current end of the chain. Anchoring that
checkpoint in a separate trust domain closes the gap the chain alone cannot: an attacker who holds
the key can rewrite the whole log so that `verify()` passes again, but the rewritten hash will no
longer match the checkpoint you anchored elsewhere.

`verifyAgainstCheckpoint(anchor)` runs the internal verification, rejects a chain that no longer
reaches the anchored sequence (`TRUNCATED`), and then compares the anchored hash, reporting
`CHECKPOINT_MISMATCH` if the record at that sequence no longer matches.

One limit worth being clear about: a checkpoint pins the chain **up to its own sequence**. An
attacker holding the key can still rewrite everything after the last anchor and it will verify. How
much that matters depends on how often you anchor.
