import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const read = p => readFileSync(new URL('../'+p, import.meta.url), 'utf8');
test('SSO worker is independent of Church source paths', () => {
  for (const path of ['recovered/index.js','recovery.ts','sms.ts','security.ts']) {
    const source=read(path);
    assert.doesNotMatch(source, /\.\.\/\.\.\/src\/security|\.\.\/\.\.\/\.\.\/src\/security/);
  }
});
test('migration worker cannot claim the production hostname', () => {
  const cfg=JSON.parse(read('wrangler.jsonc'));
  assert.equal(cfg.name,'domislink-sso-gateway-migration');
  assert.equal(cfg.routes,undefined);
  assert.equal(cfg.d1_databases,undefined);
});
test('OIDC issuer remains unchanged', () => {
  const cfg=JSON.parse(read('wrangler.jsonc'));
  assert.equal(cfg.vars.SSO_ISSUER,'https://sso.domislink.com');
});
