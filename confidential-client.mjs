const hex=bytes=>Array.from(new Uint8Array(bytes),b=>b.toString(16).padStart(2,'0')).join('');
export async function hashClientSecret(secret){
 if(typeof secret!=='string'||!/^[0-9a-f]{64}$/.test(secret))throw Error('Invalid client secret');
 return hex(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(secret)));
}
export async function generateClientSecret(){
 const secret=hex(crypto.getRandomValues(new Uint8Array(32)));
 return {secret,secretHash:await hashClientSecret(secret)};
}
export async function authenticateClient({record,secret}){
 if(record===null)return secret===null;
 if(!record||typeof record.secret_hash!=='string'||!/^[0-9a-f]{64}$/.test(record.secret_hash))return false;
 let actual;try{actual=await hashClientSecret(secret)}catch{return false}
 let diff=0;for(let i=0;i<64;i++)diff|=actual.charCodeAt(i)^record.secret_hash.charCodeAt(i);
 return diff===0;
}

export async function authenticateTokenClient(db,form){
 for(const key of ['client_id','client_secret','grant_type','code','redirect_uri','code_verifier','refresh_token','token']){
  const values=form.getAll(key);if(values.length>1||values.some(v=>typeof v!=='string'))return false;
 }
 const id=form.get('client_id');if(typeof id!=='string'||!id||id.length>256)return false;
 const row=await db.prepare('SELECT c.client_id, s.secret_hash FROM sso_clients c LEFT JOIN sso_confidential_clients s ON s.client_id=c.client_id WHERE c.client_id=? AND c.enabled=1').bind(id).first();
 if(!row||row.client_id!==id)return false;
 return authenticateClient({record:row.secret_hash===null?null:row,secret:form.get('client_secret')});
}

export async function registerConfidentialClient(db,{clientId,name,redirects,scopes,now}){
 if(typeof clientId!=='string'||!/^dl_[A-Za-z0-9_-]{20,128}$/.test(clientId)||typeof name!=='string'||!name.trim()||name.length>200||!Array.isArray(redirects)||!redirects.length||redirects.length>20||new Set(redirects).size!==redirects.length||!Array.isArray(scopes)||!scopes.includes('openid')||scopes.some(s=>!['openid','profile','email','phone'].includes(s)))throw Error('Invalid confidential registration');
 for(const uri of redirects){if(typeof uri!=='string'||uri.length>2048)throw Error('Invalid redirect');const u=new URL(uri);if(u.protocol!=='https:'||u.username||u.password||u.hash||uri.includes('#'))throw Error('Invalid redirect')}
 const {secret,secretHash}=await generateClientSecret();
 const results=await db.batch([
  db.prepare('INSERT INTO sso_clients(client_id,client_name,redirect_uris,allowed_scopes,enabled,created_at) VALUES(?,?,?,?,1,?)').bind(clientId,name,JSON.stringify(redirects),scopes.join(' '),now),
  db.prepare('INSERT INTO sso_confidential_clients(client_id,secret_hash,created_at) VALUES(?,?,?)').bind(clientId,secretHash,now)
 ]);
 if(!Array.isArray(results)||results.length!==2||results.some(r=>r.success!==true))throw Error('Registration failed');
 return {client_id:clientId,client_name:name,redirect_uris:redirects,allowed_scopes:scopes,client_secret:secret,token_endpoint_auth_method:'client_secret_post'};
}

export async function rotateConfidentialClient(db,{clientId,previousHash}){
 if(typeof clientId!=='string'||!/^dl_[A-Za-z0-9_-]{20,128}$/.test(clientId)||typeof previousHash!=='string'||!/^[0-9a-f]{64}$/.test(previousHash))throw Error('Invalid rotation');
 const {secret,secretHash}=await generateClientSecret();
 const row=await db.prepare('UPDATE sso_confidential_clients SET secret_hash=? WHERE client_id=? AND secret_hash=? AND EXISTS (SELECT 1 FROM sso_clients c WHERE c.client_id=sso_confidential_clients.client_id AND c.enabled=1) RETURNING client_id').bind(secretHash,clientId,previousHash).first();
 if(!row||row.client_id!==clientId)throw Error('Rotation conflict');
 return {client_id:clientId,client_secret:secret};
}
export async function revokeConfidentialClient(db,clientId){
 if(typeof clientId!=='string'||!/^dl_[A-Za-z0-9_-]{20,128}$/.test(clientId))throw Error('Invalid revocation');
 const row=await db.prepare('UPDATE sso_clients SET enabled=0 WHERE client_id=? AND enabled=1 AND EXISTS (SELECT 1 FROM sso_confidential_clients s WHERE s.client_id=sso_clients.client_id) RETURNING client_id').bind(clientId).first();
 return row?.client_id===clientId;
}

export function guardedGrantInsert(db,table,{tokenHash,clientId,userId,scope,expiresAt,credentialHash}){
 if(!['sso_access_tokens','sso_refresh_tokens'].includes(table))throw Error('Invalid grant table');
 if(credentialHash!==null&&(typeof credentialHash!=='string'||!/^[0-9a-f]{64}$/.test(credentialHash)))throw Error('Invalid credential proof');
 return db.prepare('INSERT INTO '+table+'(token_hash,client_id,user_id,scope,expires_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM sso_clients c LEFT JOIN sso_confidential_clients s ON s.client_id=c.client_id WHERE c.client_id=? AND c.enabled=1 AND s.secret_hash IS ?)').bind(tokenHash,clientId,userId,scope,expiresAt,clientId,credentialHash);
}
export function requireGrantPair(results){
 if(!Array.isArray(results)||results.length!==2||results.some(r=>r.success!==true||r.meta?.changes!==1))throw Error('Client credential changed');
}
