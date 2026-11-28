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
 for(const key of ['client_id','client_secret','grant_type','code','redirect_uri','code_verifier','refresh_token']){
  const values=form.getAll(key);if(values.length>1||values.some(v=>typeof v!=='string'))return false;
 }
 const id=form.get('client_id');if(typeof id!=='string'||!id||id.length>256)return false;
 const row=await db.prepare('SELECT c.client_id, s.secret_hash FROM sso_clients c LEFT JOIN sso_confidential_clients s ON s.client_id=c.client_id WHERE c.client_id=? AND c.enabled=1').bind(id).first();
 if(!row||row.client_id!==id)return false;
 return authenticateClient({record:row.secret_hash===null?null:row,secret:form.get('client_secret')});
}
