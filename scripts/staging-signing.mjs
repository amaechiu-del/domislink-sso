import {generateKeyPairSync,createPrivateKey,createPublicKey,createHash,randomBytes} from 'node:crypto';
export function validateSigningPair(privatePem,publicPem){
 const priv=createPrivateKey(privatePem),pub=createPublicKey(publicPem);
 if(priv.asymmetricKeyType!=='rsa'||pub.asymmetricKeyType!=='rsa'||priv.asymmetricKeyDetails.modulusLength<2048)throw Error('Invalid RSA signing pair');
 const derived=createPublicKey(priv).export({type:'spki',format:'der'}),actual=pub.export({type:'spki',format:'der'});
 if(!derived.equals(actual))throw Error('Signing key mismatch');
 return {fingerprint:createHash('sha256').update(actual).digest('hex'),modulusLength:priv.asymmetricKeyDetails.modulusLength};
}
export function generateStagingSecrets(){
 const pair=generateKeyPairSync('rsa',{modulusLength:3072,privateKeyEncoding:{type:'pkcs8',format:'pem'},publicKeyEncoding:{type:'spki',format:'pem'}});
 return {OIDC_PRIVATE_KEY_PEM:pair.privateKey,OIDC_PUBLIC_KEY_PEM:pair.publicKey,SSO_ADMIN_API_KEY:randomBytes(32).toString('hex')};
}
