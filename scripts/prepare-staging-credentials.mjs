import {inspectStagingSecrets} from './staging-secret-inventory.mjs';
import {generateStagingSecrets,validateSigningPair} from './staging-signing.mjs';
// Local preparation only: no secret installation, no network writes.
export async function prepareStagingCredentials({config,accountId,token,freeTierVerified,fetcher=fetch}){
 if(freeTierVerified!==true)throw Error('Free tier confirmation required');
 const inventory=await inspectStagingSecrets({config,accountId,token,fetcher});
 if(inventory.present.length!==0)throw Error('Existing credentials require separate rotation approval');
 const secrets=generateStagingSecrets();
 const signing=validateSigningPair(secrets.OIDC_PRIVATE_KEY_PEM,secrets.OIDC_PUBLIC_KEY_PEM);
 return {secrets,signing,installationAuthorized:false};
}
