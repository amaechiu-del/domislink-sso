import {validateStaging} from './validate-staging.mjs';
import {verifyAccountDatabase} from './account-api.mjs';
export async function verifyDeployedVersion({config,accountId,token,expectedVersionId,fetcher=fetch}){
 validateStaging(config);
 if(typeof expectedVersionId!=='string'||! /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(expectedVersionId))throw Error('Expected version ID required');
 await verifyAccountDatabase({accountId,databaseId:config.d1_databases[0].database_id,token,fetcher});
 const url='https://api.cloudflare.com/client/v4/accounts/'+accountId+'/workers/scripts/'+config.name+'/deployments';
 const response=await fetcher(url,{method:'GET',headers:{Authorization:'Bearer '+token},redirect:'error',signal:AbortSignal.timeout(15000)});
 if(!response.ok)throw Error('Deployment inventory unavailable');
 const body=await response.json();
 const deployments=body?.result?.deployments;
 if(body?.success!==true||!Array.isArray(deployments)||!deployments.length)throw Error('Deployment inventory rejected');
 // API returns most recent deployment first; reject ambiguous or split traffic.
 const active=deployments[0];
 if(!Array.isArray(active?.versions)||active.versions.length!==1||active.versions[0].version_id!==expectedVersionId||active.versions[0].percentage!==100)throw Error('Expected version is not exclusively deployed');
 return {versionVerified:true,versionId:expectedVersionId,artifactIdentityVerified:false,deploymentAuthorized:false};
}
