CREATE TABLE IF NOT EXISTS sso_engineering_runners (
 runner_id TEXT PRIMARY KEY,
 secret_hash TEXT NOT NULL CHECK(length(secret_hash)=64),
 created_at TEXT NOT NULL,
 revoked_at TEXT
);
