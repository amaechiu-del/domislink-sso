import {readFile,writeFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {inspectBootstrapTarget} from './bootstrap-target.mjs';
import {verifyBootstrapHealth} from './verify-bootstrap-health.mjs';
import {inspectStagingSecrets} from './staging-secret-inventory.mjs';
export async function main(args,env,{read=readFile,write=writeFile,inspect=inspectBootstrapTarget,health=verifyBootstrapHealth,inventory=inspectStagingSecrets,log=console.log}={}){
 const [phase,path,output]=args;
 if(!['plan-bootstrap','inspect-bootstrap'].includes(phase)||!path||args.length!==(phase==='plan-bootstrap'?3:2)||env.DOMISLINK_FREE_TIER_CONFIRMED!=='true'||!env.CLOUDFLARE_ACCOUNT_ID||!env.CLOUDFLARE_API_TOKEN)return 2;
 try{
 const config=JSON.parse(await read(path,'utf8'));
 const options={config,accountId:env.CLOUDFLARE_ACCOUNT_ID,token:env.CLOUDFLARE_API_TOKEN,freeTierVerified:true};
 if(phase==='plan-bootstrap'){
 const plan=await inspect(options);
 if(plan.workerAbsentInInventory!==true||plan.deploymentAuthorized!==false)throw Error('Unexpected plan');
 await write(output,JSON.stringify(plan.config,null,2)+'\n',{flag:'wx',mode:0o600});
 log(JSON.stringify({bootstrapPlanWritten:true,deploymentAuthorized:false,atomicCreateGuaranteed:false}));
 }else{
 const status=await health(options);
 const names=await inventory(options);
 log(JSON.stringify({bootstrapHealthVerified:status.bootstrapHealthVerified===true,artifactIdentityVerified:false,allSecretsPresent:names.allPresent===true,deploymentAuthorized:false}));
 }
 return 0;
 }catch{log('Staging preflight failed; no remote changes requested.');return 1}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)process.exitCode=await main(process.argv.slice(2),process.env);
