import { hashPassword, randomToken, sha256, readCookie } from '../../src/security';
type Env={DB:D1Database;RESEND_API_KEY?:string};
type Views={forgot:(csrf:string,error?:string)=>string;reset:(email:string,csrf:string,error?:string)=>string;send:(env:Env,email:string,code:string)=>Promise<void>;limit:(env:Env,key:string,limit:number,window:number,now:Date)=>Promise<boolean>};
const cookie=(value:string,age=300)=>`dl_sso_csrf=${encodeURIComponent(value)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${age}`;
const headers=(csrf?:string)=>({'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",...(csrf?{'Set-Cookie':cookie(csrf)}:{})});
export async function handleRecovery(request:Request,env:Env,path:string,view:Views):Promise<Response|null>{
 if(!['/forgot-password','/reset-password'].includes(path))return null;
 const reset=path==='/reset-password';
 const html=(email='',message='',status=200)=>{const csrf=randomToken(24);return new Response(reset?view.reset(email,csrf,message):view.forgot(csrf,message),{status,headers:headers(csrf)});};
 if(request.method==='GET')return html(new URL(request.url).searchParams.get('email')||'');
 if(request.method!=='POST')return new Response('Method not allowed',{status:405,headers:{Allow:'GET, POST','Cache-Control':'no-store'}});
 const origin=request.headers.get('Origin');if(origin&&origin!==new URL(request.url).origin)return new Response('Origin not allowed',{status:403,headers:headers()});
 const raw=await request.text();if(raw.length>4096)return new Response('Request too large',{status:413,headers:headers()});
 const form=new URLSearchParams(raw);const csrf=form.get('csrf')||'';
 if(!csrf||csrf!==readCookie(request.headers.get('Cookie')||undefined,'dl_sso_csrf'))return html('','Your request expired. Please try again.',403);
 const email=(form.get('email')||'').trim().toLowerCase();
 if(email.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return html('','Enter a valid email address.',400);
 const now=new Date(),nowIso=now.toISOString(),destinationHash=await sha256(email);
 const network=await sha256(request.headers.get('CF-Connecting-IP')||'unknown');
 if(!reset){
  const generic=()=>new Response(null,{status:303,headers:{Location:'/reset-password?email='+encodeURIComponent(email),'Set-Cookie':cookie(randomToken(24)),'Cache-Control':'no-store'}});
  const minute=await view.limit(env,'recovery:minute:'+destinationHash,1,60000,now);
  const address=await view.limit(env,'recovery:address:'+destinationHash,3,900000,now);
  const ip=await view.limit(env,'recovery:ip:'+network,20,900000,now);
  if(!minute||!address||!ip)return generic();
  const user=await env.DB.prepare("SELECT id FROM users WHERE email=? AND status='active' LIMIT 1").bind(email).first<{id:string}>();
  if(!user||!env.RESEND_API_KEY)return generic();
  const bytes=crypto.getRandomValues(new Uint32Array(1)),code=String(bytes[0]%1000000).padStart(6,'0'),id=randomToken(32);
  await env.DB.prepare("INSERT INTO sso_verification_challenges(id,channel,purpose,destination_hash,ip_hash,code_hash,attempts,created_at,expires_at) VALUES(?,'email','password_reset',?,?,?,0,?,?)").bind(id,destinationHash,network,await sha256(id+'.'+code),nowIso,new Date(now.getTime()+600000).toISOString()).run();
  try{await view.send(env,email,code);}catch{await env.DB.prepare('UPDATE sso_verification_challenges SET consumed_at=? WHERE id=?').bind(nowIso,id).run();}
  return generic();
 }
 const code=form.get('code')||'',password=form.get('newPassword')||'',confirm=form.get('confirmPassword')||'';
 if(!/^\d{6}$/.test(code)||password.length<12||password.length>128||password!==confirm)return html(email,'Enter the six-digit code and matching passwords of 12–128 characters.',400);
 if(!await view.limit(env,'recovery:complete:'+network,20,900000,now))return html(email,'Too many attempts. Please try again later.',429);
 const challenge=await env.DB.prepare("SELECT id,code_hash FROM sso_verification_challenges WHERE channel='email' AND purpose='password_reset' AND destination_hash=? AND consumed_at IS NULL AND expires_at>? ORDER BY created_at DESC LIMIT 1").bind(destinationHash,nowIso).first<{id:string;code_hash:string}>();
 const fail=()=>html(email,'The verification code is invalid or expired. Request a new code.',400);
 if(!challenge)return fail();
 const attempt=await env.DB.prepare('UPDATE sso_verification_challenges SET attempts=attempts+1 WHERE id=? AND attempts<5 AND consumed_at IS NULL AND expires_at>? RETURNING attempts').bind(challenge.id,nowIso).first<{attempts:number}>();
 if(!attempt||challenge.code_hash!==await sha256(challenge.id+'.'+code))return fail();
 const user=await env.DB.prepare("SELECT id FROM users WHERE email=? AND status='active' LIMIT 1").bind(email).first<{id:string}>();if(!user)return fail();
 const hashed=await hashPassword(password),claim=await sha256(randomToken(32)),claimedAt=new Date().toISOString();
 // A consumed code no longer needs its OTP hash. Replace it with a unique claim
 // inside the same transaction that updates the password and revokes grants.
 const own='EXISTS(SELECT 1 FROM sso_verification_challenges WHERE id=? AND code_hash=? AND consumed_at=?)';
 const gate=[challenge.id,claim,claimedAt];
 const statements=[
  env.DB.prepare('UPDATE sso_verification_challenges SET consumed_at=?,code_hash=? WHERE id=? AND code_hash=? AND consumed_at IS NULL AND attempts<=5 AND expires_at>?').bind(claimedAt,claim,challenge.id,challenge.code_hash,claimedAt),
  env.DB.prepare(`UPDATE users SET password_hash=?,updated_at=? WHERE id=? AND status='active' AND ${own}`).bind(hashed,claimedAt,user.id,...gate),
  ...['sessions','sso_sessions','sso_authorization_codes','sso_church_setup_tokens'].map(table=>env.DB.prepare(`DELETE FROM ${table} WHERE user_id=? AND ${own}`).bind(user.id,...gate)),
  env.DB.prepare(`DELETE FROM oidc_auth_transactions WHERE church_user_id=? AND ${own}`).bind(user.id,...gate),
  ...['sso_access_tokens','sso_refresh_tokens'].map(table=>env.DB.prepare(`UPDATE ${table} SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL AND ${own}`).bind(claimedAt,user.id,...gate)),
  env.DB.prepare(`UPDATE sso_verification_challenges SET consumed_at=? WHERE destination_hash=? AND consumed_at IS NULL AND ${own}`).bind(claimedAt,destinationHash,...gate)
 ];
 const results=await env.DB.batch(statements);if(!results[0]?.meta?.changes||!results[1]?.meta?.changes)return fail();
 return new Response(null,{status:303,headers:{Location:'/login','Set-Cookie':cookie('',0),'Cache-Control':'no-store'}});
}
