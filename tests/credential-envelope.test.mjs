import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateStagingSecrets} from '../scripts/staging-signing.mjs';
import {sealCredentials,unsealCredentials,saveCredentialEnvelope} from '../scripts/credential-envelope.mjs';
test('encrypted custody binds credentials to staging identity and refuses overwrite',async()=>{
 const config=JSON.parse(await readFile(new URL('../wrangler.confidential-staging.example.jsonc',import.meta.url),'utf8'));
 const host=config.name+'.fixture.workers.dev';
 Object.assign(config.vars,{APP_ORIGIN:'https://'+host,SSO_ISSUER:'https://'+host,WEBAUTHN_RP_ID:host});
 config.d1_databases[0].database_id='12345678-1234-1234-1234-123456789abc';
 const secrets=generateStagingSecrets(),password=Buffer.from('fixture-only-long-passphrase'),accountId='a'.repeat(32);
 const options={config,secrets,password,accountId};
 const envelope=sealCredentials(options);
 assert.ok(!envelope.includes(secrets.SSO_ADMIN_API_KEY));assert.ok(!envelope.includes('PRIVATE KEY'));
 assert.notEqual(envelope,sealCredentials(options));
 assert.deepEqual(unsealCredentials({...options,envelope}),secrets);
 assert.throws(()=>unsealCredentials({...options,envelope,accountId:'b'.repeat(32)}),/rejected/);
 assert.throws(()=>unsealCredentials({...options,envelope,password:Buffer.from('incorrect-long-passphrase')}),/rejected/);
 const tampered=JSON.parse(envelope);tampered.tag=(tampered.tag[0]==='0'?'1':'0')+tampered.tag.slice(1);
 assert.throws(()=>unsealCredentials({...options,envelope:JSON.stringify(tampered)}),/rejected/);
 const dir=await mkdtemp(join(tmpdir(),'sso-custody-'));try{
 const path=join(dir,'backup.enc');await saveCredentialEnvelope({...options,path});
 await assert.rejects(saveCredentialEnvelope({...options,path}),{code:'EEXIST'});
 assert.deepEqual(unsealCredentials({...options,envelope:await readFile(path,'utf8')}),secrets);
 }finally{password.fill(0);await rm(dir,{recursive:true,force:true})}
});
