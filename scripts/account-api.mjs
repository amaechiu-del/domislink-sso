// Read-only Cloudflare API identity probe. Token supplied by trusted operator, never returned.
export async function verifyAccountDatabase({accountId,databaseId,token,fetcher=fetch}){
 if(typeof accountId!=='string'||typeof databaseId!=='string'||!/^[a-f0-9]{32}$/.test(accountId)||!/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(databaseId)||typeof token!=='string'||!token.trim())throw Error('Valid scoped credentials required');
 const root='https://api.cloudflare.com/client/v4/accounts/'+accountId;
 async function get(path){
  let response;
  try{response=await fetcher(root+path,{method:'GET',headers:{Authorization:'Bearer '+token},redirect:'error',signal:AbortSignal.timeout(15000)});}catch{throw Error('Cloudflare identity transport failed');}
  if(!response.ok)throw Error('Cloudflare identity request failed');
  let body;
  try{body=await response.json();}catch{throw Error('Cloudflare identity response unreadable');}
  if(!body||body.success!==true||!body.result)throw Error('Cloudflare identity response rejected');
  return body.result;
 }
 const account=await get('');
 if(account.id!==accountId)throw Error('Account mismatch');
 const db=await get('/d1/database/'+databaseId);
 if(db.uuid!==databaseId||db.name!=='domislink-sso-confidential-staging-db')throw Error('Dedicated database mismatch');
 return {accountId,databaseId,identityVerified:true,freeTierVerified:false,executeAuthorized:false};
}
