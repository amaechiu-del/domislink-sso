# Registry integration acceptance

Reuse the existing domislink-services-registry repository. Do not create a duplicate identity service.

Staging issuer: https://domislink-sso-registry-staging.amaechi-u.workers.dev
Audience: domislink-central-services-registry
Algorithm: RS256
Key discovery: /oauth/jwks
Reader: services:read
Administrator: services:read services:write AND domislink:services:admin

The consumer must verify signatures with the pinned issuer's JWKS, issuer, audience, expiration, not-before and subject. Reject opaque tokens, unknown keys, invalid signatures and missing required scopes. Do not accept production tokens in staging or staging tokens in production. Never use the ID token as the API access token.

## Acceptance gates

- Confirm the actual Registry callback URL from its repository and register exactly that URL.
- Keep public staging access disabled until controlled test access is approved.
- The loopback PKCE harness requires a separately approved exact http://localhost:8765/callback redirect on the staging client. The HTTPS-only registration script does not register that redirect.
- Confirm active staging user subjects before installing grants.
- Run local tests, staging readiness, discovery/JWKS and browser PKCE checks.
- Verify actual reader/admin JWTs and negative cases against the Registry API.
- Check anonymous, wrong issuer, wrong audience, expired and tampered tokens return 401; valid reader writes return 403.
- Grant removal takes effect for new tokens; existing JWTs may remain valid for up to 900 seconds.
- Registration is not server-idempotent. After ambiguous failure inspect the staging database before retrying.
- No production deployment, new database or paid service is authorized by this document.

This contract is not a deployed consumer integration.
