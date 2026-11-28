import {prepareBootstrapConfig} from './prepare-bootstrap.mjs';
// Read-only inventory; absence is a snapshot, not an atomic create-only guarantee.
export async function inspectBootstrapTarget(options){
 const plan=await prepareBootstrapConfig(options);
 const {accountId,token,fetcher=fetch}=options;
 const url='https://api.cloudflare.com/client/v4/accounts/'+accountId+'/workers/scripts';
 const response=await fetcher(url,{method:'GET',headers:{Authorization:'Bearer '+token},redirect:'error',signal:AbortSignal.timeout(15000)});
 if(!response.ok)throw Error('Worker inventory unavailable');
 const body=await response.json();
 if(body?.success!==true||!Array.isArray(body.result)||body.result.some(x=>typeof x?.id!=='string'||!x.id))throw Error('Worker inventory rejected');
 const info=body.result_info;
 if(info&&(info.total_count!==body.result.length||(info.total_pages!==undefined&&info.total_pages>1)||(info.page!==undefined&&info.page!==1)||info.cursor||info.cursors?.after))throw Error('Incomplete Worker inventory');
 if(body.result.some(x=>x.id===plan.config.name))throw Error('Existing staging Worker must not be replaced');
 return {...plan,workerAbsentInInventory:true,atomicCreateGuaranteed:false,deploymentAuthorized:false};
}
