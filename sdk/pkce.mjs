const issuers={production:"https://sso.domislink.com",staging:"https://domislink-sso-registry-staging.amaechi-u.workers.dev"};
const b64=bytes=>btoa(String.fromCharCode(...bytes)).replaceAll("+","-").replaceAll("/","_").replace(/=+$/,"");
const random=()=>b64(crypto.getRandomValues(new Uint8Array(32)));
export async function beginAuthorization({environment,clientId,redirectUri}){
 const issuer=issuers[environment];
 if(!issuer||!/^dl_[A-Za-z0-9_-]+$/.test(clientId))throw Error("Invalid client configuration");
 const redirect=new URL(redirectUri);
 if(redirect.protocol!=="https:"||redirect.username||redirect.password||redirect.hash)throw Error("Invalid redirect");
 if(environment==="staging"&&!redirect.hostname.endsWith(".workers.dev"))throw Error("Staging callback required");
 const verifier=random(),state=random(),nonce=random();
 const challenge=b64(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(verifier))));
 const url=new URL(issuer+"/oauth/authorize");
 url.search=new URLSearchParams({client_id:clientId,redirect_uri:redirectUri,response_type:"code",scope:"openid profile email",state,nonce,code_challenge:challenge,code_challenge_method:"S256"}).toString();
 return {url:url.href,transaction:{issuer,clientId,redirectUri,verifier,state,nonce,expiresAt:Date.now()+300000}};
}
export async function exchangeAuthorization(transaction,callbackUrl){
 const t=transaction,u=new URL(callbackUrl),expected=new URL(t.redirectUri);
 if(!Object.values(issuers).includes(t.issuer)||Date.now()>=t.expiresAt||u.origin!==expected.origin||u.pathname!==expected.pathname||u.searchParams.getAll("state").length!==1||u.searchParams.get("state")!==t.state||u.searchParams.getAll("code").length!==1||!u.searchParams.get("code")||u.searchParams.has("error"))throw Error("Invalid authorization callback");
 const r=await fetch(t.issuer+"/oauth/token",{method:"POST",redirect:"error",signal:AbortSignal.timeout(15000),body:new URLSearchParams({grant_type:"authorization_code",client_id:t.clientId,redirect_uri:t.redirectUri,code:u.searchParams.get("code"),code_verifier:t.verifier})});
 if(!r.ok)throw Error("Token exchange failed");
 const result=await r.json();
 if(typeof result.id_token!=="string"||typeof result.access_token!=="string")throw Error("Invalid token response");
 return result;
}
// Caller must store transaction server-side, consume it atomically once, and verify ID token signature, issuer, audience, expiry and nonce before creating a session.
