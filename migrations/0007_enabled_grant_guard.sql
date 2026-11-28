CREATE TRIGGER IF NOT EXISTS sso_access_tokens_enabled_insert
BEFORE INSERT ON sso_access_tokens
WHEN NOT EXISTS(SELECT 1 FROM sso_clients WHERE client_id=NEW.client_id AND enabled=1)
BEGIN SELECT RAISE(ABORT,'client disabled'); END;
CREATE TRIGGER IF NOT EXISTS sso_refresh_tokens_enabled_insert
BEFORE INSERT ON sso_refresh_tokens
WHEN NOT EXISTS(SELECT 1 FROM sso_clients WHERE client_id=NEW.client_id AND enabled=1)
BEGIN SELECT RAISE(ABORT,'client disabled'); END;
CREATE TRIGGER IF NOT EXISTS sso_authorization_codes_enabled_insert
BEFORE INSERT ON sso_authorization_codes
WHEN NOT EXISTS(SELECT 1 FROM sso_clients WHERE client_id=NEW.client_id AND enabled=1)
BEGIN SELECT RAISE(ABORT,'client disabled'); END;
