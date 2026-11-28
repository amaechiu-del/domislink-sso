import {readFileSync} from 'node:fs';
import {inspectStagingSecrets} from './staging-secret-inventory.mjs';
try{console.log(JSON.stringify(await inspectStagingSecrets({config:JSON.parse(readFileSync(process.argv[2],'utf8')),accountId:process.env.CLOUDFLARE_ACCOUNT_ID,token:process.env.CLOUDFLARE_API_TOKEN})))}catch{console.error('Staging secret inventory failed');process.exitCode=1}
