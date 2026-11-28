import {authenticateRunner,registerRunner,revokeRunner} from './runner-registry.mjs';
import {issueRunnerToken} from './runner-token.mjs';
const reply=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','Pragma':'no-cache'}});
export async function handleRunner(request,env,sign){
 const path=new URL(request.url).pathname;
 if(!path.startsWith('/internal/runners'))return null;
 if(env.WORKER!=='domislink-sso-confidential-staging'||request.method!=='POST'||request.headers.has('Origin'))return reply({error:'not_found'},404);
 if(path==='/internal/runners/register'||path==='/internal/runners/revoke'){
  if(!env.SSO_ADMIN_API_KEY||request.headers.get('Authorization')!=='Bearer '+env.SSO_ADMIN_API_KEY)return reply({error:'unauthorized'},401);
  if(path.endsWith('/register'))return reply(await registerRunner(env.DB),201);
  let body;try{body=await request.json()}catch{return reply({error:'invalid_request'},400)}
  return reply({revoked:await revokeRunner(env.DB,body?.runner_id)});
 }
 if(path!=='/internal/runners/token')return reply({error:'not_found'},404);
 let body;try{body=await request.json()}catch{return reply({error:'invalid_request'},400)}
 if(!await authenticateRunner(env.DB,body?.runner_id,body?.runner_secret))return reply({error:'invalid_client'},401);
 const token=await issueRunnerToken({subject:body.runner_id,issuer:env.SSO_ISSUER,sign});
 if(!await authenticateRunner(env.DB,body.runner_id,body.runner_secret))return reply({error:'invalid_client'},401);
 return reply({access_token:token,token_type:'Bearer',expires_in:300,scope:'rapidbuild:run'});
}
