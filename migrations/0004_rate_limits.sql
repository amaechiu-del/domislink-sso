-- Atomic, privacy-preserving rate limits for universal identity OTP delivery.
CREATE TABLE IF NOT EXISTS sso_rate_limits (
  rate_key TEXT PRIMARY KEY,
  window_started_at TEXT NOT NULL,
  hits INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sso_rate_limits_expiry ON sso_rate_limits(expires_at);
