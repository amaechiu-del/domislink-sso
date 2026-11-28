import {readFileSync} from 'node:fs';
import {validateStaging} from './validate-staging.mjs';
import {verifyAccountDatabase} from './account-api.mjs';
try {
 const c=JSON.parse(readFileSync(process.argv[2],'utf8'));
 validateStaging(c);
 console.log(JSON.stringify(await verifyAccountDatabase({accountId:process.env.CLOUDFLARE_ACCOUNT_ID,databaseId:c.d1_databases[0].database_id,token:process.env.CLOUDFLARE_API_TOKEN})));
}catch{console.error('Staging identity verification failed');process.exitCode=1}
