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
 interruption_transaction_no TEXT,
 end_date TEXT,
 status TEXT NOT NULL DEFAULT 'waiting_region',
 requester_id INTEGER NOT NULL,
 region_user_id INTEGER,
 original_region_user_id INTEGER,
 delegated_from_user_id INTEGER,
 delegated_at TEXT,
 region_note TEXT,
 requester_note TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 region_responded_at TEXT,
 final_approved_at TEXT,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 cancelled_at TEXT,
 stopped_at TEXT
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

CREATE TABLE IF NOT EXISTS regions (
 name TEXT PRIMARY KEY,
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS delegations (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 record_id INTEGER NOT NULL,
 from_user_id INTEGER,
 to_user_id INTEGER NOT NULL,
 delegated_by INTEGER NOT NULL,
 reason TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS assignment_rules (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 source_user_id INTEGER NOT NULL,
 target_user_id INTEGER NOT NULL,
 rule_type TEXT NOT NULL,
 created_by INTEGER NOT NULL,
 reason TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 expires_at TEXT,
 active INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_records_status ON records(status);
CREATE INDEX IF NOT EXISTS idx_records_region ON records(region);
CREATE INDEX IF NOT EXISTS idx_records_employee ON records(employee_no);
CREATE INDEX IF NOT EXISTS idx_records_region_user ON records(region_user_id);
CREATE INDEX IF NOT EXISTS idx_records_requester ON records(requester_id);
CREATE INDEX IF NOT EXISTS idx_assignment_rules_source ON assignment_rules(source_user_id,active);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
