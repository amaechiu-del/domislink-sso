-- DomisLink Universal Identity: verified email/phone and device passkeys
CREATE TABLE IF NOT EXISTS sso_verification_challenges (
  id TEXT PRIMARY KEY,
  channel TEXT NOT NULL CHECK(channel IN ('email','phone')),
  purpose TEXT NOT NULL DEFAULT 'signin',
  destination_hash TEXT NOT NULL,
  ip_hash TEXT,
  code_hash TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sso_verification_destination ON sso_verification_challenges(channel,destination_hash,created_at);
CREATE INDEX IF NOT EXISTS idx_sso_verification_expiry ON sso_verification_challenges(expires_at);
CREATE TABLE IF NOT EXISTS sso_verified_phones (
  phone_e164 TEXT PRIMARY KEY,
  user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  verified_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sso_webauthn_challenges (
  challenge_hash TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL CHECK(purpose IN ('registration','authentication')),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sso_webauthn_expiry ON sso_webauthn_challenges(expires_at);
CREATE TABLE IF NOT EXISTS sso_passkeys (
  credential_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key_json TEXT NOT NULL,
  algorithm INTEGER NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  transports_json TEXT NOT NULL DEFAULT '[]',
  device_name TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sso_passkeys_user ON sso_passkeys(user_id);

-- Expose verified phone numbers to OIDC clients only when the phone scope is requested.
UPDATE sso_clients SET allowed_scopes=CASE WHEN instr(' ' || allowed_scopes || ' ',' phone ') > 0 THEN allowed_scopes ELSE allowed_scopes || ' phone' END;

CREATE INDEX IF NOT EXISTS idx_sso_verification_ip ON sso_verification_challenges(ip_hash,created_at);

-- One-time handoff for verified DomisLink IDs that are creating their first church workspace.
CREATE TABLE IF NOT EXISTS sso_church_setup_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sso_church_setup_expiry ON sso_church_setup_tokens(expires_at);
