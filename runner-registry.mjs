import {generateClientSecret,authenticateClient} from './confidential-client.mjs';
const valid=id=>typeof id==='string'&&/^runner_[A-Za-z0-9_-]{16,128}$/.test(id);
export async function registerRunner(db){
 const runnerId='runner_'+crypto.randomUUID().replaceAll('-','');
 const {secret,secretHash}=await generateClientSecret();
 const row=await db.prepare('INSERT INTO sso_engineering_runners(runner_id,secret_hash,created_at) VALUES(?,?,?) RETURNING runner_id').bind(runnerId,secretHash,new Date().toISOString()).first();
 if(row?.runner_id!==runnerId)throw Error('Runner registration failed');
 return {runner_id:runnerId,runner_secret:secret};
}
export async function authenticateRunner(db,id,secret){
 if(!valid(id)||typeof secret!=='string')return false;
 const row=await db.prepare('SELECT runner_id,secret_hash FROM sso_engineering_runners WHERE runner_id=? AND revoked_at IS NULL').bind(id).first();
 return row?.runner_id===id&&await authenticateClient({record:row,secret});
}
export async function revokeRunner(db,id){
 if(!valid(id))return false;
 const row=await db.prepare('UPDATE sso_engineering_runners SET revoked_at=? WHERE runner_id=? AND revoked_at IS NULL RETURNING runner_id').bind(new Date().toISOString(),id).first();
 return row?.runner_id===id;
}
