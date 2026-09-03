-- Append-only table for the audit chain. To make append-only a real guarantee, grant the audit
-- database role INSERT and SELECT on this table but not UPDATE or DELETE.
--
-- format_version records the canonical encoding each row's hash was computed under, so rows written
-- by an older build stay verifiable after the encoding changes. Without it, changing the format
-- would make every existing row report as tampered with.
CREATE TABLE IF NOT EXISTS audit_chain (
    sequence       BIGINT        NOT NULL PRIMARY KEY,
    format_version SMALLINT      NOT NULL,
    timestamp_ms   BIGINT        NOT NULL,
    actor          VARCHAR(255),
    action         VARCHAR(255)  NOT NULL,
    resource_type  VARCHAR(255),
    resource_id    VARCHAR(255),
    details        VARCHAR(4000) NOT NULL,
    previous_hash  CHAR(64)      NOT NULL,
    hash           CHAR(64)      NOT NULL
);

-- The tip of each chain: one row per audit table. This table does two jobs.
--
-- 1. It serializes appends. A hash chain cannot be built in parallel, because a record cannot be
--    sealed until the one before it is settled. Appending locks this row first, so two writers form
--    an orderly queue instead of both claiming the same sequence number and one of them losing its
--    record.
--
-- 2. record_count is a high-water mark that only ever grows. Deleting the newest rows from
--    audit_chain leaves a shorter but perfectly valid chain, so the hash links cannot reveal it;
--    comparing the rows present against this count is what makes that deletion visible.
--
-- This table needs UPDATE, unlike audit_chain. Grant it separately and to nothing else. An attacker
-- who can write here can hide a truncation, so the protection is only as good as that separation.
-- Whoever can change this row can also stall appends, but cannot forge a record: the hashes still
-- have to line up.
CREATE TABLE IF NOT EXISTS audit_chain_head (
    chain_table    VARCHAR(255) NOT NULL PRIMARY KEY,
    last_sequence  BIGINT       NOT NULL,
    last_hash      CHAR(64)     NOT NULL,
    record_count   BIGINT       NOT NULL,
    updated_ms     BIGINT       NOT NULL
);

-- Seed the tip row. A row lock can only serialize writers if there is a row to lock, so without
-- this the very first appends on a fresh chain race each other and one of them is rejected. Written
-- as an idempotent INSERT ... WHERE NOT EXISTS so it is safe to run on every startup and works on
-- every database, unlike the various UPSERT dialects.
INSERT INTO audit_chain_head (chain_table, last_sequence, last_hash, record_count, updated_ms)
SELECT 'audit_chain', -1,
       '0000000000000000000000000000000000000000000000000000000000000000', 0, 0
WHERE NOT EXISTS (SELECT 1 FROM audit_chain_head WHERE chain_table = 'audit_chain');
