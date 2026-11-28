import {validateStaging} from './validate-staging.mjs';
import {verifyAccountDatabase} from './account-api.mjs';
export const requiredSecrets=Object.freeze(['OIDC_PRIVATE_KEY_PEM','OIDC_PUBLIC_KEY_PEM','SSO_ADMIN_API_KEY']);
export async function inspectStagingSecrets({config,accountId,token,fetcher=fetch}){
 validateStaging(config);
 await verifyAccountDatabase({accountId,databaseId:config.d1_databases[0].database_id,token,fetcher});
 let response;
 try{response=await fetcher('https://api.cloudflare.com/client/v4/accounts/'+accountId+'/workers/scripts/'+config.name+'/secrets',{method:'GET',headers:{Authorization:'Bearer '+token},redirect:'error',signal:AbortSignal.timeout(15000)});}catch{throw Error('Secret inventory transport failed')}
 if(!response.ok)throw Error('Secret inventory unavailable');
 let body;try{body=await response.json()}catch{throw Error('Secret inventory unreadable')}
 if(body.success!==true||!Array.isArray(body.result)||body.result.some(x=>typeof x?.name!=='string'))throw Error('Secret inventory rejected');
 const names=new Set(body.result.filter(x=>x.type==='secret_text').map(x=>x.name));
 const present=requiredSecrets.filter(x=>names.has(x)),missing=requiredSecrets.filter(x=>!names.has(x));
 return {present,missing,allPresent:missing.length===0,installationAuthorized:false,valuesVerified:false};
}
