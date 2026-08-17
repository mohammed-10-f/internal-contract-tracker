-- V13 additions that are safe on an existing D1 database.
CREATE TABLE IF NOT EXISTS record_stages (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 record_id INTEGER NOT NULL,
 stage TEXT NOT NULL,
 user_id INTEGER,
 started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 ended_at TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_record_stages_record ON record_stages(record_id);
CREATE INDEX IF NOT EXISTS idx_record_stages_stage ON record_stages(stage);

CREATE TABLE IF NOT EXISTS delegations_v2 (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 source_user_id INTEGER NOT NULL,
 target_user_id INTEGER NOT NULL,
 starts_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 ends_at TEXT,
 active INTEGER NOT NULL DEFAULT 1,
 created_by INTEGER,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 revoked_at TEXT,
 revoked_by INTEGER,
 note TEXT
);
CREATE INDEX IF NOT EXISTS idx_delegations_source ON delegations_v2(source_user_id, active);
CREATE INDEX IF NOT EXISTS idx_delegations_target ON delegations_v2(target_user_id, active);


-- V15: performance metadata marker is created by the Worker; this migration remains idempotent.
CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
