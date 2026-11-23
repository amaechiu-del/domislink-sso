# Database migration runbook (not yet executed)

## Scope
The four numbered SQL files establish a *new, empty* standalone identity schema. They are NOT a production data migration and must not be run against the existing Church database.

## Data preservation
Export the current users, sso_clients, sso_sessions, sso_authorization_codes, sso_access_tokens, sso_refresh_tokens, sso_verification_challenges, sso_verified_phones, sso_webauthn_challenges, sso_passkeys, sso_church_setup_tokens, and sso_rate_limits tables from the current authoritative D1 database. Verify schema columns and indexes against production before importing.

Maintain user IDs, password hashes, client IDs, token hashes, expirations, revocations, credential counters and account associations unchanged. Never export OIDC private keys into Git or logs. Preserve Cloudflare Worker secrets separately using restricted deployment configuration.

## Execution order
1. Take a verified, access-controlled backup and record table counts and schema.
2. Create an isolated staging D1 database.
3. Apply 0001–0004 to staging using Wrangler, inspect every SQL result.
4. Import a protected copy of identity data in foreign-key order, with users and clients before dependent records.
5. Compare counts, referential integrity, sample identity records, and cryptographic compatibility.
6. Bind only the staging Worker to staging D1. Confirm OIDC discovery, PKCE, JWKS, login, refresh, OTP, passkeys and Church account linking.
7. Plan a short write freeze or dual-write strategy for production cutover; replay changes since snapshot.
8. Switch the production route only after approved end-to-end verification, monitored rollback, and key continuity checks.

Do not repoint the production issuer to an empty database. Any export containing personal data must remain outside source control.
