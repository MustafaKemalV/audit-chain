# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately, through
[GitHub's private advisory form](https://github.com/MustafaKemalV/audit-chain/security/advisories/new).
Please do not open a public issue first.

Include what you need to make the problem reproducible: the version, the store you are using, and
the smallest sequence of steps that shows it. A failing test or a short program is ideal.

You can expect an acknowledgement within a week, and an assessment of whether the report is in scope
within two.

## What is in scope

This library is tamper-**evident**, not tamper-proof. It does not stop anyone from changing the
database; it makes the change visible when the log is verified. A report is in scope if it shows
tampering that `verify()` reports as intact, within the assumptions below.

In scope:

- Altering, removing, reordering or adding records without `verify()` reporting it.
- Moving records between chains sealed with the same key.
- Making `verify()` throw, hang, or report a break that did not happen. Verification is meant to be
  total: any content the tables can hold should produce a verdict.
- Losing an audit record that the library accepted, under concurrency or otherwise.
- Recording an action whose business transaction was rolled back, or failing to record one that
  committed.

Out of scope, because these are the library's stated limits rather than defects:

- An attacker holding the HMAC key. HMAC is symmetric: whoever can verify can also sign. Anchoring a
  checkpoint in a separate trust domain is the answer, and its limits are documented.
- An attacker who can write to `audit_chain_head` hiding a truncation by lowering the remembered
  count, or stopping the chain by setting the tip behind the records. That table's grants are what
  this protection is worth, which the README states.
- Anything above the last anchored checkpoint, for a key holder.
- An action that never reached the library at all.
- An attacker with `INSERT` on the audit table stopping future appends by occupying the next
  sequence. The records already written stay verifiable and the forged row is reported; this costs
  availability, not evidence.
- Connection-pool exhaustion when `on-failure=LOG` or read-only auditing is used without sizing the
  pool for two connections per audited request. See Operational requirements in the README.

See the threat model in [README.md](README.md) for the full picture.

## Supported versions

Until 1.0, only the latest released version is supported.
