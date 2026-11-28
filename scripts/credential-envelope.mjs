import {randomBytes,scryptSync,createCipheriv,createDecipheriv} from 'node:crypto';
import {open} from 'node:fs/promises';
import {validateStaging} from './validate-staging.mjs';
import {validateSigningPair} from './staging-signing.mjs';
const exact=(o,keys)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join(',')===keys.split(',').sort().join(',');
function target(config,accountId){
 validateStaging(config);
 if(typeof accountId!=='string'||!/^[a-f0-9]{32}$/.test(accountId))throw Error('Invalid account');
 return JSON.stringify({version:1,accountId,databaseId:config.d1_databases[0].database_id,worker:config.name,issuer:config.vars.SSO_ISSUER});
}
function validateSecrets(s){
 if(!exact(s,'OIDC_PRIVATE_KEY_PEM,OIDC_PUBLIC_KEY_PEM,SSO_ADMIN_API_KEY')||Object.values(s).some(v=>typeof v!=='string'||v.length>16384)||!/^[a-f0-9]{64}$/.test(s.SSO_ADMIN_API_KEY))throw Error('Invalid credentials');
 validateSigningPair(s.OIDC_PRIVATE_KEY_PEM,s.OIDC_PUBLIC_KEY_PEM);
}
function key(password,salt){
 if(!Buffer.isBuffer(password)||password.length<16||password.length>1024)throw Error('Passphrase must be a buffer of 16 to 1024 bytes');
 return scryptSync(password,salt,32,{N:32768,r:8,p:1,maxmem:64*1024*1024});
}
export function sealCredentials({config,accountId,secrets,password}){
 const aad=target(config,accountId);validateSecrets(secrets);
 const salt=randomBytes(32),nonce=randomBytes(12),k=key(password,salt);
 const plain=Buffer.from(JSON.stringify(secrets));
 try{
 const cipher=createCipheriv('aes-256-gcm',k,nonce);cipher.setAAD(Buffer.from(aad));
 const ciphertext=Buffer.concat([cipher.update(plain),cipher.final()]);
 return JSON.stringify({version:1,target:aad,salt:salt.toString('hex'),nonce:nonce.toString('hex'),tag:cipher.getAuthTag().toString('hex'),ciphertext:ciphertext.toString('hex')});
 }finally{k.fill(0);plain.fill(0)}
}
export function unsealCredentials({config,accountId,envelope,password}){
 let k,plain;
 try{
 const aad=target(config,accountId);
 if(typeof envelope!=='string'||envelope.length>131072)throw Error();
 const e=JSON.parse(envelope);
 if(!exact(e,'version,target,salt,nonce,tag,ciphertext')||e.version!==1||e.target!==aad)throw Error();
 for(const [field,len] of [['salt',64],['nonce',24],['tag',32]])if(typeof e[field]!=='string'||e[field].length!==len||!/^[a-f0-9]+$/.test(e[field]))throw Error();
 if(typeof e.ciphertext!=='string'||! /^(?:[a-f0-9]{2})+$/.test(e.ciphertext))throw Error();
 k=key(password,Buffer.from(e.salt,'hex'));
 const decipher=createDecipheriv('aes-256-gcm',k,Buffer.from(e.nonce,'hex'));decipher.setAAD(Buffer.from(aad));decipher.setAuthTag(Buffer.from(e.tag,'hex'));
 plain=Buffer.concat([decipher.update(Buffer.from(e.ciphertext,'hex')),decipher.final()]);
 const secrets=JSON.parse(plain.toString('utf8'));validateSecrets(secrets);return secrets;
 }catch{throw Error('Credential recovery rejected')}finally{k?.fill(0);plain?.fill(0)}
}
export async function saveCredentialEnvelope({path,...options}){
 const envelope=sealCredentials(options);
 const file=await open(path,'wx',0o600);
 try{await file.writeFile(envelope,'utf8');await file.sync()}finally{await file.close()}
 return {encryptedBackupWritten:true,installationAuthorized:false};
}
