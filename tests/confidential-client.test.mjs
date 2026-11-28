import test from 'node:test';import assert from 'node:assert/strict';
import {generateClientSecret,authenticateClient} from '../confidential-client.mjs';
test('public clients remain public and reject supplied secrets',async()=>{assert.equal(await authenticateClient({record:null,secret:null}),true);assert.equal(await authenticateClient({record:null,secret:'bad'}),false)});
test('confidential clients require exact generated secret',async()=>{const a=await generateClientSecret(),b=await generateClientSecret();assert.notEqual(a.secret,b.secret);const record={secret_hash:a.secretHash};assert.equal(await authenticateClient({record,secret:a.secret}),true);assert.equal(await authenticateClient({record,secret:b.secret}),false);assert.equal(await authenticateClient({record,secret:null}),false)});
test('malformed or missing lookup fails closed',async()=>{assert.equal(await authenticateClient({record:undefined,secret:null}),false);assert.equal(await authenticateClient({record:{secret_hash:'bad'},secret:null}),false)});

import {authenticateTokenClient} from '../confidential-client.mjs';
const dbFor=row=>({prepare:sql=>{assert.match(sql,/c.enabled=1/);return {bind:id=>({first:async()=>row})}}});
const formFor=(secret)=>{const f=new FormData();f.set('client_id','dl_test');f.set('grant_type','authorization_code');if(secret!==null)f.set('client_secret',secret);return f};
test('token gate checks enabled registered public clients',async()=>{assert.equal(await authenticateTokenClient(dbFor({client_id:'dl_test',secret_hash:null}),formFor(null)),true);assert.equal(await authenticateTokenClient(dbFor(null),formFor(null)),false)});
test('token gate requires confidential secret and rejects duplicate fields',async()=>{const a=await generateClientSecret(),db=dbFor({client_id:'dl_test',secret_hash:a.secretHash});assert.equal(await authenticateTokenClient(db,formFor(a.secret)),true);assert.equal(await authenticateTokenClient(db,formFor(null)),false);const f=formFor(a.secret);f.append('client_id','other');assert.equal(await authenticateTokenClient(db,f),false)});

import {registerConfidentialClient} from '../confidential-client.mjs';
const registration={clientId:'dl_'+ 'a'.repeat(24),name:'AI Studio',redirects:['https://studio.example.com/callback'],scopes:['openid','email'],now:'2026-11-28T00:00:00Z'};
test('registration batches both inserts and never stores plaintext',async()=>{let writes;const db={prepare:sql=>({bind:(...args)=>({sql,args})}),batch:async statements=>{writes=statements;return [{success:true},{success:true}]}};const result=await registerConfidentialClient(db,registration);assert.equal(writes.length,2);assert.equal(writes[1].args[1],await (await import('../confidential-client.mjs')).hashClientSecret(result.client_secret));assert.ok(!JSON.stringify(writes).includes(result.client_secret));assert.equal(result.token_endpoint_auth_method,'client_secret_post')});
test('registration rejects unsafe redirects before database access',async()=>{for(const uri of ['http://example.com','https://user@example.com','https://example.com/#fragment'])await assert.rejects(registerConfidentialClient({}, {...registration,redirects:[uri]}))});
test('failed batch does not return a credential',async()=>{const db={prepare:()=>({bind:()=>({})}),batch:async()=>{throw Error('rollback')}};await assert.rejects(registerConfidentialClient(db,registration),/rollback/)});

import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import {rotateConfidentialClient,revokeConfidentialClient} from '../confidential-client.mjs';
test('real SQLite registration rollback, rotation CAS and revocation preserve confidentiality',async()=>{
 const raw=new DatabaseSync(':memory:');try{
 raw.exec('PRAGMA foreign_keys=ON; CREATE TABLE sso_clients(client_id TEXT PRIMARY KEY,client_name TEXT,redirect_uris TEXT,allowed_scopes TEXT,enabled INTEGER,created_at TEXT);');
 raw.exec(readFileSync(new URL('../migrations/0005_confidential_clients.sql',import.meta.url),'utf8'));
 const db={prepare:sql=>({bind:(...args)=>({sql,args,first:async()=>raw.prepare(sql).get(...args)??null})}),batch:async statements=>{raw.exec('BEGIN');try{for(const s of statements)raw.prepare(s.sql).run(...s.args);raw.exec('COMMIT');return statements.map(()=>({success:true}))}catch(e){raw.exec('ROLLBACK');throw e}}};
 raw.exec("CREATE TRIGGER reject_secret BEFORE INSERT ON sso_confidential_clients BEGIN SELECT RAISE(ABORT,'fixture failure'); END;");
 await assert.rejects(registerConfidentialClient(db,registration));assert.equal(raw.prepare('SELECT count(*) n FROM sso_clients').get().n,0);
 raw.exec('DROP TRIGGER reject_secret');
 const a=await registerConfidentialClient(db,registration);const old=raw.prepare('SELECT secret_hash FROM sso_confidential_clients').get().secret_hash;
 const form=secret=>{const f=formFor(secret);f.set('client_id',registration.clientId);return f};
 assert.equal(await authenticateTokenClient(db,form(a.client_secret)),true);
 const rotated=await rotateConfidentialClient(db,{clientId:registration.clientId,previousHash:old});
 await assert.rejects(rotateConfidentialClient(db,{clientId:registration.clientId,previousHash:old}),/conflict/);
 assert.equal(await authenticateTokenClient(db,form(a.client_secret)),false);
 assert.equal(await authenticateTokenClient(db,form(rotated.client_secret)),true);
 assert.equal(await revokeConfidentialClient(db,registration.clientId),true);
 assert.equal(await authenticateTokenClient(db,form(rotated.client_secret)),false);
 assert.equal(await authenticateTokenClient(db,form(null)),false);
 assert.equal(raw.prepare('SELECT count(*) n FROM sso_confidential_clients').get().n,1);
 }finally{raw.close()}
});
