-- V20 is migrated by src/worker.js because D1 installations may be on different legacy versions.
-- This file documents the target model for environments that execute SQL migrations separately.
-- The live Worker performs the data-preserving rebuild and status conversion idempotently.
UPDATE schema_meta SET value='23' WHERE key='version';
