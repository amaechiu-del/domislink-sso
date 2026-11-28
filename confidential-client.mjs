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
