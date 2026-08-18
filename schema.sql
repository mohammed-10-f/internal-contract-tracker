CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 name TEXT NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'viewer',
 region TEXT,
 permissions TEXT DEFAULT '',
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS records (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 employee_no TEXT NOT NULL,
 employee_name TEXT NOT NULL,
 region TEXT NOT NULL,
 start_date TEXT NOT NULL,
 transaction_no TEXT,
 transaction_date TEXT,
 interruption_transaction_no TEXT,
 end_date TEXT,
 status TEXT NOT NULL DEFAULT 'waiting_region',
 requester_id INTEGER NOT NULL,
 region_user_id INTEGER,
 region_note TEXT,
 requester_note TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 region_responded_at TEXT,
 final_approved_at TEXT,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 timer_paused_at TEXT,
 timer_end_at TEXT,
 paused_seconds INTEGER NOT NULL DEFAULT 0,
 stage_started_at TEXT,
 original_region_user_id INTEGER,
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
CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires_at INTEGER NOT NULL,login_at TEXT DEFAULT CURRENT_TIMESTAMP,last_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,logout_at TEXT,ip TEXT,user_agent TEXT);
CREATE INDEX IF NOT EXISTS idx_records_status ON records(status);
CREATE INDEX IF NOT EXISTS idx_records_region ON records(region);
CREATE INDEX IF NOT EXISTS idx_records_employee ON records(employee_no);
CREATE INDEX IF NOT EXISTS idx_records_manager ON records(region_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_record ON audit_log(record_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_expires ON sessions(token,expires_at);
CREATE INDEX IF NOT EXISTS idx_records_region_status_created ON records(region_user_id,status,created_at);
CREATE INDEX IF NOT EXISTS idx_records_requester_status ON records(requester_id,status);
CREATE INDEX IF NOT EXISTS idx_records_delegated_status ON records(delegated_to_user_id,status);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

CREATE TABLE IF NOT EXISTS regions (name TEXT PRIMARY KEY, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);


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
