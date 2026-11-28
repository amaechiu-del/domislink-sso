import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import {revokeConfidentialClient} from '../confidential-client.mjs';
test('disable atomically revokes only targeted persisted grants',async()=>{
 const db=new DatabaseSync(':memory:');try{
 db.exec('PRAGMA foreign_keys=ON; CREATE TABLE users(id TEXT PRIMARY KEY);');
 for(const file of ['0002_oidc_core.sql','0005_confidential_clients.sql','0006_confidential_revocation.sql','0007_enabled_grant_guard.sql'])db.exec(readFileSync(new URL('../migrations/'+file,import.meta.url),'utf8'));
 db.exec("INSERT INTO users VALUES('u')");
 const a='dl_'+'a'.repeat(24),b='dl_'+'b'.repeat(24);
 for(const id of [a,b]){
 db.prepare("INSERT INTO sso_clients VALUES(?,?,?,'openid',1,'now')").run(id,id,'[]');
 db.prepare("INSERT INTO sso_confidential_clients VALUES(?,?,'now')").run(id,'a'.repeat(64));
 for(const table of ['sso_access_tokens','sso_refresh_tokens'])db.prepare("INSERT INTO "+table+"(token_hash,client_id,user_id,scope,expires_at) VALUES(?,?,'u','openid','later')").run(id,id);
 db.prepare("INSERT INTO sso_authorization_codes(code_hash,client_id,user_id,redirect_uri,code_challenge,scope,expires_at) VALUES(?,?,'u','https://example.com','x','openid','later')").run(id,id);
 }
 const adapter={prepare:sql=>({bind:(...args)=>({first:async()=>db.prepare(sql).get(...args)})})};
 assert.equal(await revokeConfidentialClient(adapter,a),true);
 for(const [table,col] of [['sso_access_tokens','revoked_at'],['sso_refresh_tokens','revoked_at'],['sso_authorization_codes','used_at']]){
 assert.ok(db.prepare('SELECT '+col+' v FROM '+table+' WHERE client_id=?').get(a).v);
 assert.equal(db.prepare('SELECT '+col+' v FROM '+table+' WHERE client_id=?').get(b).v,null);
 }
 for(const table of ['sso_access_tokens','sso_refresh_tokens'])assert.throws(()=>db.prepare("INSERT INTO "+table+"(token_hash,client_id,user_id,scope,expires_at) VALUES(?,?,'u','openid','later')").run('late',a),/client disabled/);
 assert.throws(()=>db.prepare("INSERT INTO sso_authorization_codes(code_hash,client_id,user_id,redirect_uri,code_challenge,scope,expires_at) VALUES(?,?,'u','https://example.com','x','openid','later')").run('late',a),/client disabled/);
 db.prepare("INSERT INTO sso_access_tokens(token_hash,client_id,user_id,scope,expires_at) VALUES(?,?,'u','openid','later')").run('unrelated',b);
 assert.equal(await revokeConfidentialClient(adapter,a),false);
 }finally{db.close()}
});

import {guardedGrantInsert,requireGrantPair} from '../confidential-client.mjs';
test('grant insertion rejects stale secret hash and accepts current hash',()=>{
 const db=new DatabaseSync(':memory:');try{
 db.exec('CREATE TABLE users(id TEXT PRIMARY KEY);');
 for(const file of ['0002_oidc_core.sql','0005_confidential_clients.sql','0007_enabled_grant_guard.sql'])db.exec(readFileSync(new URL('../migrations/'+file,import.meta.url),'utf8'));
 db.exec("INSERT INTO users VALUES('u'); INSERT INTO sso_clients VALUES('c','c','[]','openid',1,'now')");
 db.prepare("INSERT INTO sso_confidential_clients VALUES('c',?,'now')").run('b'.repeat(64));
 const adapter={prepare:sql=>({bind:(...args)=>({run:()=>db.prepare(sql).run(...args)})})};
 const grant={tokenHash:'t',clientId:'c',userId:'u',scope:'openid',expiresAt:'later'};
 for(const table of ['sso_access_tokens','sso_refresh_tokens']){
 assert.equal(guardedGrantInsert(adapter,table,{...grant,credentialHash:'a'.repeat(64)}).run().changes,0);
 assert.equal(guardedGrantInsert(adapter,table,{...grant,credentialHash:null}).run().changes,0);
 assert.equal(guardedGrantInsert(adapter,table,{...grant,credentialHash:'b'.repeat(64)}).run().changes,1);
 }
 assert.throws(()=>requireGrantPair([{success:true,meta:{changes:0}},{success:true,meta:{changes:0}}]));
 }finally{db.close()}
});
