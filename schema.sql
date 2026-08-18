CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 name TEXT NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'viewer',
 permissions TEXT DEFAULT '',
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS records (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 employee_no TEXT NOT NULL,
 employee_name TEXT NOT NULL,
 start_date TEXT NOT NULL,
 transaction_no TEXT,
 transaction_date TEXT,
 interruption_transaction_no TEXT,
 end_date TEXT,
 status TEXT NOT NULL DEFAULT 'waiting_responsible',
 requester_id INTEGER NOT NULL,
 responsible_user_id INTEGER,
 responsible_note TEXT,
 requester_note TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 responsible_responded_at TEXT,
 final_approved_at TEXT,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 timer_paused_at TEXT,
 timer_end_at TEXT,
 paused_seconds INTEGER NOT NULL DEFAULT 0,
 stage_started_at TEXT,
 original_responsible_user_id INTEGER,
 delegated_from_user_id INTEGER,
 delegated_at TEXT,
 stopped_at TEXT,
 stopped_by INTEGER,
 completed_at TEXT,
 delegated_to_user_id INTEGER
);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 record_id INTEGER,
 user_id INTEGER,
 action TEXT NOT NULL,
 note TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
 token TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 login_at TEXT DEFAULT CURRENT_TIMESTAMP,
 last_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,
 logout_at TEXT,
 ip TEXT,
 user_agent TEXT
);
CREATE TABLE IF NOT EXISTS record_stages (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 record_id INTEGER NOT NULL,
 stage TEXT NOT NULL,
 user_id INTEGER,
 started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 ended_at TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS delegations_v2 (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 source_user_id INTEGER NOT NULL,
 target_user_id INTEGER NOT NULL,
 starts_at TEXT,
 ends_at TEXT,
 active INTEGER NOT NULL DEFAULT 1,
 created_by INTEGER,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 revoked_at TEXT,
 revoked_by INTEGER,
 note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO schema_meta(key,value) VALUES('version','23') ON CONFLICT(key) DO UPDATE SET value=excluded.value;
CREATE INDEX IF NOT EXISTS idx_records_status ON records(status);
CREATE INDEX IF NOT EXISTS idx_records_employee ON records(employee_no);
CREATE INDEX IF NOT EXISTS idx_records_responsible ON records(responsible_user_id);
CREATE INDEX IF NOT EXISTS idx_records_responsible_status_created ON records(responsible_user_id,status,created_at);
CREATE INDEX IF NOT EXISTS idx_records_requester_status ON records(requester_id,status);
CREATE INDEX IF NOT EXISTS idx_records_delegated_status ON records(delegated_to_user_id,status);
CREATE INDEX IF NOT EXISTS idx_records_created ON records(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_record ON audit_log(record_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_token_expires ON sessions(token,expires_at);
CREATE INDEX IF NOT EXISTS idx_record_stages_record ON record_stages(record_id);
CREATE INDEX IF NOT EXISTS idx_record_stages_stage ON record_stages(stage);
CREATE INDEX IF NOT EXISTS idx_delegations_source_active ON delegations_v2(source_user_id,active,starts_at,ends_at);
CREATE INDEX IF NOT EXISTS idx_delegations_target_active ON delegations_v2(target_user_id,active,starts_at,ends_at);
