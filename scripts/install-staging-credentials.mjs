import {inspectStagingSecrets,requiredSecrets} from './staging-secret-inventory.mjs';
import {validateSigningPair} from './staging-signing.mjs';
export async function installStagingCredentials(options){
 const {config,accountId,token,fetcher=fetch,secrets,freeTierVerified,confirmInstallation,exclusiveOperatorConfirmed}=options;
 if(freeTierVerified!==true||confirmInstallation!==true||exclusiveOperatorConfirmed!==true)throw Error('Explicit installation and exclusive operator confirmation required');
 if(!secrets||Object.keys(secrets).length!==3||requiredSecrets.some(k=>typeof secrets[k]!=='string')||! /^[a-f0-9]{64}$/.test(secrets.SSO_ADMIN_API_KEY))throw Error('Invalid credential set');
 const signing=validateSigningPair(secrets.OIDC_PRIVATE_KEY_PEM,secrets.OIDC_PUBLIC_KEY_PEM);
 const inventory=await inspectStagingSecrets(options);
 if(inventory.present.length!==0)throw Error('Existing credentials require separate rotation approval');
 const url='https://api.cloudflare.com/client/v4/accounts/'+accountId+'/workers/scripts/'+config.name+'/secrets';
 try{
 for(const name of requiredSecrets){
 const response=await fetcher(url,{method:'PUT',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({name,text:secrets[name],type:'secret_text'}),redirect:'error',signal:AbortSignal.timeout(15000)});
 if(!response.ok||(await response.json())?.success!==true)throw Error('Write rejected');
 }
 const after=await inspectStagingSecrets(options);
 if(!after.allPresent)throw Error('Inventory incomplete');
 }catch{throw Error('Installation uncertain or partial; stop and reconcile inventory. Do not retry automatically.')}
 return {allPresent:true,fingerprint:signing.fingerprint,valuesVerified:false,deploymentAuthorized:false};
}
