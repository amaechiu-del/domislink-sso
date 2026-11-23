# Staging D1 provisioning

The repository currently has a **local-only D1 binding** in `wrangler.local.jsonc`. Its UUID is a placeholder used only for Wrangler's local simulator, **not a real Cloudflare database**.

Run `npm install`, `npm test`, and `npm run db:local:verify` to apply and inspect the isolated local schema.

To provision remote staging, an authorized operator should run:

```powershell
npx wrangler login
npx wrangler d1 create domislink-sso-staging-db
```

Copy the returned real database ID into a separate `wrangler.staging.jsonc` configuration, binding `DB` and setting `migrations_dir` to `migrations`. Do not configure a production route. Verify that the account and database are the intended staging resources before running:

```powershell
npx wrangler d1 migrations apply domislink-sso-staging-db --remote --config wrangler.staging.jsonc
```

The staging database is empty until data is explicitly and securely imported. The current production identity database and hostname must remain untouched.
