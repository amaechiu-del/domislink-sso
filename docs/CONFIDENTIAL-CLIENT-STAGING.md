# Confidential client staging gate

Live AI Studio discovery reported missing client_secret_post (operator exit 2). This branch adds an additive credential table and high-entropy secret helpers only. No gateway routes or discovery metadata are changed yet. Existing public PKCE clients remain unchanged. Before wiring, verify authoritative deployed source, require enabled client lookup, authenticate before consuming authorization codes or refresh tokens, reject duplicate form fields, implement atomic registration and rotation, and test public and confidential flows. Never advertise support until implemented. Runner issuance is separate. No production migration or deployment authorized.

## Discovery compatibility checkpoint

HTTP gateway exchange CI passed at 33eef90 (run 46159719059). Discovery now advertises none and client_secret_post for token and revocation endpoints in this branch. This is not live issuer certification. Dedicated staging must verify the actual issuer, D1 migrations, signing keys, browser authorization redirects and public-client regression before release. Runner token issuance remains a separate gate.
