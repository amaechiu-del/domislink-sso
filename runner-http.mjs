import {authenticateRunner,registerRunner,revokeRunner} from './runner-registry.mjs';
import {issueRunnerToken} from './runner-token.mjs';
const reply=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','Pragma':'no-cache'}});
async function readBody(request,fields){
 if(request.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase()!=='application/json')throw Error('Invalid content type');
 const length=request.headers.get('Content-Length');
 if(length!==null&&(!/^\d+$/.test(length)||Number(length)>2048))throw Error('Invalid length');
 const reader=request.body?.getReader();if(!reader)throw Error('Missing body');
 let size=0;const chunks=[];
 try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>2048){await reader.cancel();throw Error('Oversized body')}chunks.push(value)}}finally{reader.releaseLock()}
 const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length}
 const body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).sort().join(',')!==fields.slice().sort().join(','))throw Error('Invalid fields');
 if(fields.includes('runner_id')&&(typeof body.runner_id!=='string'||!/^runner_[A-Za-z0-9_-]{16,128}$/.test(body.runner_id)))throw Error('Invalid runner ID');
 if(fields.includes('runner_secret')&&(typeof body.runner_secret!=='string'||! /^[0-9a-f]{64}$/.test(body.runner_secret)))throw Error('Invalid secret');
 return body;
}
async function allowAttempt(env,key,limit){
 const now=new Date(),start=new Date(Math.floor(now.getTime()/60000)*60000).toISOString(),expiry=new Date(Date.parse(start)+60000).toISOString();
 const row=await env.DB.prepare(`INSERT INTO sso_rate_limits(rate_key,window_started_at,hits,expires_at) VALUES(?,?,1,?)
 ON CONFLICT(rate_key) DO UPDATE SET hits=CASE WHEN window_started_at<excluded.window_started_at THEN 1 ELSE MIN(hits+1,?) END,window_started_at=MAX(window_started_at,excluded.window_started_at),expires_at=MAX(expires_at,excluded.expires_at) RETURNING hits`).bind('engineering-runner:'+key,start,expiry,limit+1).first();
 return Number.isSafeInteger(row?.hits)&&row.hits>=1&&row.hits<=limit;
}
export async function handleRunner(request,env,sign){
 const path=new URL(request.url).pathname;
 if(!path.startsWith('/internal/runners'))return null;
 if(env.WORKER!=='domislink-sso-confidential-staging'||request.method!=='POST'||request.headers.has('Origin'))return reply({error:'not_found'},404);
 if(path==='/internal/runners/register'||path==='/internal/runners/revoke'){
  if(!env.SSO_ADMIN_API_KEY||request.headers.get('Authorization')!=='Bearer '+env.SSO_ADMIN_API_KEY)return reply({error:'unauthorized'},401);
  let body;try{body=await readBody(request,path.endsWith('/register')?[]:['runner_id'])}catch{return reply({error:'invalid_request'},400)}
  if(!await allowAttempt(env,'admin',30))return reply({error:'rate_limited'},429);
  if(path.endsWith('/register'))return reply(await registerRunner(env.DB),201);
  return reply({revoked:await revokeRunner(env.DB,body?.runner_id)});
 }
 if(path!=='/internal/runners/token')return reply({error:'not_found'},404);
 let body;try{body=await readBody(request,['runner_id','runner_secret'])}catch{return reply({error:'invalid_request'},400)}
 if(!await allowAttempt(env,'token-global',120))return reply({error:'rate_limited'},429);
 if(!await authenticateRunner(env.DB,body?.runner_id,body?.runner_secret))return reply({error:'invalid_client'},401);
 if(!await allowAttempt(env,'token:'+body.runner_id,12))return reply({error:'rate_limited'},429);
 const token=await issueRunnerToken({subject:body.runner_id,issuer:env.SSO_ISSUER,sign});
 if(!await authenticateRunner(env.DB,body.runner_id,body.runner_secret))return reply({error:'invalid_client'},401);
 return reply({access_token:token,token_type:'Bearer',expires_in:300,scope:'rapidbuild:run'});
}
