import {validateStaging} from './validate-staging.mjs';
import {verifyAccountDatabase} from './account-api.mjs';
export async function prepareBootstrapConfig({config,accountId,token,freeTierVerified,fetcher=fetch}){
 validateStaging(config);
 if(freeTierVerified!==true)throw Error('Free tier confirmation required');
 await verifyAccountDatabase({accountId,databaseId:config.d1_databases[0].database_id,token,fetcher});
 const {name,compatibility_date,workers_dev}=config;
 return {config:{name,main:'scripts/bootstrap-worker.mjs',compatibility_date,workers_dev,vars:{WORKER:name,SSO_ISSUER:config.vars.SSO_ISSUER}},deploymentAuthorized:false};
}
