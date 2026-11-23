-- Standalone identity table. Migrate real user rows before any production cutover.
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT, full_name TEXT NOT NULL,
 phone TEXT, status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','pending')),
 email_verified_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
