-- Revoke persisted grants atomically with confidential client disabling.
CREATE TRIGGER IF NOT EXISTS sso_confidential_disable_grants
AFTER UPDATE OF enabled ON sso_clients
WHEN OLD.enabled=1 AND NEW.enabled=0 AND EXISTS(SELECT 1 FROM sso_confidential_clients WHERE client_id=NEW.client_id)
BEGIN
 UPDATE sso_access_tokens SET revoked_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE client_id=NEW.client_id AND revoked_at IS NULL;
 UPDATE sso_refresh_tokens SET revoked_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE client_id=NEW.client_id AND revoked_at IS NULL;
 UPDATE sso_authorization_codes SET used_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE client_id=NEW.client_id AND used_at IS NULL;
END;
