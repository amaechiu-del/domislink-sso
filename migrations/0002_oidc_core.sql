-- DomisLink Universal SSO + tenant-isolated WhatsApp connections
CREATE TABLE IF NOT EXISTS sso_clients (
  client_id TEXT PRIMARY KEY,
  client_name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  allowed_scopes TEXT NOT NULL DEFAULT 'openid profile email',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sso_sessions (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sso_sessions_user ON sso_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sso_sessions_expiry ON sso_sessions(expires_at);
CREATE TABLE IF NOT EXISTS sso_authorization_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES sso_clients(client_id),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  nonce TEXT,
  scope TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sso_codes_expiry ON sso_authorization_codes(expires_at);
CREATE TABLE IF NOT EXISTS sso_access_tokens (
  token_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES sso_clients(client_id),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sso_access_user ON sso_access_tokens(user_id);
CREATE TABLE IF NOT EXISTS sso_refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES sso_clients(client_id),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  rotated_to_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_sso_refresh_user ON sso_refresh_tokens(user_id);

