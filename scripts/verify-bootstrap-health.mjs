import {validateStaging} from './validate-staging.mjs';
// Public health probe uses no Cloudflare authorization header.
export async function verifyBootstrapHealth({config,healthFetcher=fetch}){
 validateStaging(config);
 const response=await healthFetcher(config.vars.SSO_ISSUER+'/health',{method:'GET',redirect:'error',cache:'no-store',signal:AbortSignal.timeout(15000)});
 if(response.status!==200)throw Error('Bootstrap health unavailable');
 const body=await response.json();
 if(body?.ok!==true||body.environment!=='staging'||body.bootstrap!==true||body.authenticationEnabled!==false||body.executionEnabled!==false)throw Error('Bootstrap health rejected');
 return {bootstrapHealthVerified:true,artifactIdentityVerified:false};
}
