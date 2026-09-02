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
