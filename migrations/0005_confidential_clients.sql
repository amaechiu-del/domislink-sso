-- Additive only; existing clients remain public PKCE.
CREATE TABLE IF NOT EXISTS sso_confidential_clients (
 client_id TEXT PRIMARY KEY REFERENCES sso_clients(client_id) ON DELETE CASCADE,
 secret_hash TEXT NOT NULL CHECK(length(secret_hash)=64),
 created_at TEXT NOT NULL
);
