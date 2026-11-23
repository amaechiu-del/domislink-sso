# SSO migration cutover gate

The existing Cloudflare Worker and Church D1 database remain authoritative.

1. Inventory all SSO tables and production migrations 0040-0042; export a consistent backup.
2. Confirm that all user IDs, password hashes, passkeys, OIDC clients, signing keys, refresh tokens, and active sessions are preserved.
3. Run build and tests in this repository, then deploy the migration worker under its separate name, without a custom production route.
4. Bind a staging D1 clone and configure required secrets through Cloudflare (never commit them).
5. Verify discovery, JWKS, PKCE, state/nonce, email and SMS verification, refresh/revocation, logout, Church account linking, and rollback.
6. Only after successful verification, explicitly approve the route and deployment ownership change to sso.domislink.com.

Do not activate production routing or point a new empty D1 database at the live issuer.
