-- Append-only table for the audit chain. To make append-only a real guarantee, grant the audit
-- database role INSERT and SELECT on this table but not UPDATE or DELETE.
CREATE TABLE IF NOT EXISTS audit_chain (
    sequence       BIGINT        NOT NULL PRIMARY KEY,
    timestamp_ms   BIGINT        NOT NULL,
    actor          VARCHAR(255),
    action         VARCHAR(255)  NOT NULL,
    resource_type  VARCHAR(255),
    resource_id    VARCHAR(255),
    details        VARCHAR(4000) NOT NULL,
    previous_hash  CHAR(64)      NOT NULL,
    hash           CHAR(64)      NOT NULL
);
