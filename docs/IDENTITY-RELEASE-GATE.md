# Identity release gate

Production remains on the existing gateway until explicit cutover approval.

| Channel | Source status | Acceptance required |
|---|---|---|
| Google | Not implemented in recovered gateway | OIDC code exchange, state/nonce, verified Google issuer and audience, stable subject mapping, explicit account linking |
| Email | Resend OTP implemented | Verified sender, successful inbox delivery, expiry, replay and rate limits |
| SMS | Termii adapter implemented | Approved sender, provider acceptance, actual handset delivery, expiry and replay |
| Passkeys | WebAuthn handlers implemented | Registration and authentication on exact staging RP, challenge replay rejection, user verification, recovery |
| Registry | Scoped access tokens implemented | Live signed token acceptance, reader/admin negative cases |

Staging OTP start is disabled unless STAGING_OTP_DELIVERY_ENABLED=true. Do not install live provider credentials or enable delivery without administrator cost approval. Audit recovery and all other provider call paths separately; the OTP start gate is not a universal spending limit.

Run npm test and the isolated staging readiness script before any deployment. Verify database bindings, secrets presence, exact callback registration, signing keys, PKCE and browser passkeys. Never publish credentials or tokens in logs. Production user migration, rollback rehearsal, provider acceptance and existing application compatibility are mandatory before cutover.

This checklist records requirements, not verified production readiness.
