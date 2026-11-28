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
