# DomisLink SSO Gateway

Independent source repository for the existing OneLink identity provider at `https://sso.domislink.com`.

## Migration status
Recovered gateway source, SMS, account recovery and password security modules have been copied from `amaechiu-del/domislink-church`. The original gateway remains the live deployment. **Do not deploy this repository until D1 schema compatibility, dependency build, secrets, routes and end-to-end OIDC flows have been verified.**

The gateway still expects the existing SSO schema in the Church D1 database. A dedicated D1 migration must preserve users, sessions, clients, authorization codes and keys before a production cutover. Do not create an empty replacement production identity database.

Run `npm install`, `npm run check`, and `npm run build` to validate locally. The production domain route is intentionally omitted from the new Wrangler configuration pending cutover.
