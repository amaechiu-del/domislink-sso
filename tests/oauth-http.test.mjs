import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import {generateKeyPairSync,createHash,verify} from 'node:crypto';
import gateway from '../recovered/index.js';
import {registerConfidentialClient} from '../confidential-client.mjs';
const digest=s=>createHash('sha256').update(s).digest('base64url');
test('actual gateway public and confidential code and refresh exchanges',async()=>{
 const raw=new DatabaseSync(':memory:');try{
 raw.exec("PRAGMA foreign_keys=ON; CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT,full_name TEXT,email_verified_at TEXT,phone TEXT,status TEXT); INSERT INTO users VALUES('u','u@example.com','Fixture','now',NULL,'active');");
 for(const file of ['0002_oidc_core.sql','0005_confidential_clients.sql','0006_confidential_revocation.sql','0007_enabled_grant_guard.sql'])raw.exec(readFileSync(new URL('../migrations/'+file,import.meta.url),'utf8'));
 const db={prepare:sql=>({bind:(...args)=>({sql,args,first:async()=>raw.prepare(sql).get(...args)??null})}),batch:async statements=>{raw.exec('BEGIN');try{const result=statements.map(s=>({success:true,meta:{changes:raw.prepare(s.sql).run(...s.args).changes}}));raw.exec('COMMIT');return result}catch(e){raw.exec('ROLLBACK');throw e}}};
 const keys=generateKeyPairSync('rsa',{modulusLength:2048});
 const env={DB:db,OIDC_PRIVATE_KEY_PEM:keys.privateKey.export({type:'pkcs8',format:'pem'}),SSO_ADMIN_API_KEY:'fixture-only'};
 const id='dl_'+'a'.repeat(24),redirect='https://studio.example.com/callback',verifier='v'.repeat(43);
 const confidential=await registerConfidentialClient(db,{clientId:id,name:'Fixture',redirects:[redirect],scopes:['openid'],now:new Date().toISOString()});
 raw.prepare("INSERT INTO sso_clients VALUES('public','Public',?,'openid',1,'now')").run(JSON.stringify([redirect]));
 const post=fields=>gateway.fetch(new Request('https://sso.domislink.com/oauth/token',{method:'POST',body:new URLSearchParams(fields)}),env);
 for(const [client,secret] of [[id,confidential.client_secret],['public',null]]){
 const code='code-'+client;
 raw.prepare("INSERT INTO sso_authorization_codes(code_hash,client_id,user_id,redirect_uri,code_challenge,scope,expires_at) VALUES(?,?,'u',?,?,'openid',?)").run(digest(code),client,redirect,digest(verifier),new Date(Date.now()+600000).toISOString());
 const fields={grant_type:'authorization_code',client_id:client,code,redirect_uri:redirect,code_verifier:verifier};
 if(secret){assert.equal((await post(fields)).status,401);fields.client_secret=secret}
 const response=await post(fields);assert.equal(response.status,200);const tokens=await response.json();assert.ok(tokens.access_token&&tokens.refresh_token);
 const [head,body,sig]=tokens.id_token.split('.');assert.ok(verify('RSA-SHA256',Buffer.from(head+'.'+body),keys.publicKey,Buffer.from(sig,'base64url')));
 assert.equal(JSON.parse(Buffer.from(body,'base64url')).aud,client);
 assert.equal((await post(fields)).status,400);
 const refresh={grant_type:'refresh_token',client_id:client,refresh_token:tokens.refresh_token};if(secret)refresh.client_secret=secret;
 const next=await post(refresh);assert.equal(next.status,200);assert.notEqual((await next.json()).refresh_token,tokens.refresh_token);
 assert.equal((await post(refresh)).status,400);
 }
 }finally{raw.close()}
});

test('discovery advertises implemented public and confidential authentication',async()=>{const response=await gateway.fetch(new Request('https://sso.domislink.com/.well-known/openid-configuration'),{});assert.equal(response.status,200);const d=await response.json();assert.deepEqual(d.token_endpoint_auth_methods_supported,['none','client_secret_post']);assert.deepEqual(d.revocation_endpoint_auth_methods_supported,['none','client_secret_post']);assert.deepEqual(d.code_challenge_methods_supported,['S256']);assert.ok(d.grant_types_supported.includes('authorization_code'));assert.ok(d.grant_types_supported.includes('refresh_token'));assert.deepEqual(d.id_token_signing_alg_values_supported,['RS256']);});

test('staging gateway rejects production origins and mismatched issuer hosts',async()=>{const origin='https://domislink-sso-confidential-staging.fixture.workers.dev';const env={WORKER:'domislink-sso-confidential-staging',SSO_ISSUER:origin,APP_ORIGIN:origin};for(const source of ['https://church.domislink.com','https://sso.domislink.com',origin]){const res=await gateway.fetch(new Request(origin+'/health',{method:'OPTIONS',headers:{Origin:source}}),env);assert.equal(res.headers.get('Access-Control-Allow-Origin'),source===origin?origin:null)}assert.equal((await gateway.fetch(new Request('https://sso.domislink.com/health'),env)).status,503);assert.equal((await gateway.fetch(new Request(origin+'/health'),{...env,SSO_ISSUER:'https://sso.domislink.com'})).status,503);});
