// Test-only exact verifier snapshot from amaechiu-del/domislink-ai-studio commit 0701de4d22a7e05cccb6c053858dc8539590f03d; refresh when contract changes.
// Internal-only short-lived OneLink runner access token verification.
// Actual SSO access token format/audience must be independently certified before use.
const decode=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
const json=s=>JSON.parse(new TextDecoder().decode(decode(s)));
export async function verifyRunnerToken(token,{jwks,now=Math.floor(Date.now()/1000),audience='domislink-rapid-build-runner',expectedIssuer='https://sso.domislink.com'}){
 if(typeof token!=='string'||token.length>16384||!Number.isSafeInteger(now)||now<0||
  (expectedIssuer!=='https://sso.domislink.com'&&!/^https:\/\/domislink-sso-confidential-staging\.[a-z0-9-]+\.workers\.dev$/.test(expectedIssuer))||
  audience!=='domislink-rapid-build-runner')throw Error('Runner token context rejected');
 const parts=token.split('.');
 if(parts.length!==3||parts.some(x=>!/^[A-Za-z0-9_-]+$/.test(x)))throw Error('Invalid bearer token');
 const [h,p,s]=parts,header=json(h),claims=json(p);
 if(header.alg!=='RS256'||typeof header.kid!=='string'||!header.kid||header.crit!==undefined)throw Error('Unsupported runner signature');
 const matches=jwks?.keys?.filter(k=>k.kid===header.kid&&k.kty==='RSA'&&(!k.alg||k.alg==='RS256')&&(!k.use||k.use==='sig'));
 if(matches?.length!==1)throw Error('Runner signing key not pinned');
 const key=await crypto.subtle.importKey('jwk',matches[0],{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
 if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,decode(s),new TextEncoder().encode(h+'.'+p)))throw Error('Invalid runner signature');
 const scopes=typeof claims.scope==='string'?claims.scope.split(' '):[];
 if(claims.iss!==expectedIssuer||claims.aud!==audience||
 claims.token_use!=='access'||typeof claims.sub!=='string'||!claims.sub||
 !Number.isSafeInteger(claims.exp)||!Number.isSafeInteger(claims.iat)||
 claims.exp<=now||claims.iat>now+30||claims.exp-claims.iat>300||claims.exp<=claims.iat||
 (claims.nbf!==undefined&&(!Number.isSafeInteger(claims.nbf)||claims.nbf>now))||
 typeof claims.jti!=='string'||!claims.jti||
 !scopes.includes('rapidbuild:run'))throw Error('Runner token claims rejected');
 return {authenticated:true,subject:claims.sub,issuer:claims.iss,capability:'test',jti:claims.jti,expiresAt:claims.exp};
}
