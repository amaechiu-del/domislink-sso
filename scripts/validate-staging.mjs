import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
export function validateStaging(c){
 const keys=(o,k)=>o&&Object.keys(o).sort().join(',')===k.split(',').sort().join(',');
 if(!keys(c,'name,main,compatibility_date,compatibility_flags,workers_dev,vars,d1_databases')||c.name!=='domislink-sso-confidential-staging'||c.main!=='recovered/index.js'||c.compatibility_date!=='2025-01-09'||JSON.stringify(c.compatibility_flags)!=='["nodejs_compat"]'||c.workers_dev!==true)throw Error('Unsafe worker configuration');
 const v=c.vars;
 if(!keys(v,'WORKER,APP_ORIGIN,SSO_ISSUER,SSO_ALLOWED_ORIGINS,OIDC_KEY_ID,WEBAUTHN_RP_ID,WEBAUTHN_RP_NAME')||!/^https:\/\/domislink-sso-confidential-staging\.[a-z0-9-]+\.workers\.dev$/.test(v.SSO_ISSUER)||v.APP_ORIGIN!==v.SSO_ISSUER||v.WORKER!==c.name||v.OIDC_KEY_ID!==c.name||v.WEBAUTHN_RP_ID!==new URL(v.SSO_ISSUER).hostname||v.WEBAUTHN_RP_NAME!=='DomisLink Staging'||v.SSO_ALLOWED_ORIGINS!=='')throw Error('Unsafe staging identity');
 const d=c.d1_databases?.[0];
 if(!Array.isArray(c.d1_databases)||c.d1_databases.length!==1||!keys(d,'binding,database_name,database_id,migrations_dir')||d.binding!=='DB'||d.database_name!=='domislink-sso-confidential-staging-db'||d.migrations_dir!=='migrations'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(d.database_id)||d.database_id==='00000000-0000-4000-8000-000000000001')throw Error('Unsafe database binding');
 return {configurationValid:true,remoteIdentityVerified:false,deploymentAuthorized:false};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){console.log(JSON.stringify(validateStaging(JSON.parse(readFileSync(process.argv[2],'utf8')))))}
