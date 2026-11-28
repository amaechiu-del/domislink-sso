import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import {revokeConfidentialClient} from '../confidential-client.mjs';
test('disable atomically revokes only targeted persisted grants',async()=>{
 const db=new DatabaseSync(':memory:');try{
 db.exec('PRAGMA foreign_keys=ON; CREATE TABLE users(id TEXT PRIMARY KEY);');
 for(const file of ['0002_oidc_core.sql','0005_confidential_clients.sql','0006_confidential_revocation.sql'])db.exec(readFileSync(new URL('../migrations/'+file,import.meta.url),'utf8'));
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
 assert.equal(await revokeConfidentialClient(adapter,a),false);
 }finally{db.close()}
});
