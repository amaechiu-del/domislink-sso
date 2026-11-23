import { execFileSync } from 'node:child_process';
const wrangler = process.platform === 'win32' ? 'node_modules/.bin/wrangler.cmd' : 'node_modules/.bin/wrangler';
function run(args) {
  execFileSync(wrangler, args, { stdio: 'inherit' });
}
run(['d1','migrations','apply','domislink-sso-local','--local','--config','wrangler.local.jsonc']);
run(['d1','execute','domislink-sso-local','--local','--config','wrangler.local.jsonc','--command','PRAGMA foreign_key_check;']);
run(['d1','execute','domislink-sso-local','--local','--config','wrangler.local.jsonc','--command',"SELECT name FROM sqlite_master WHERE type='table' AND name IN ('users','sso_clients','sso_sessions','sso_passkeys','sso_rate_limits') ORDER BY name;"]);
