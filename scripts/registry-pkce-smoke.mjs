import assert from "node:assert/strict";
import {randomBytes,createHash} from "node:crypto";
import {createServer} from "node:http";
import {readFileSync} from "node:fs";
const issuer="https://domislink-sso-registry-staging.amaechi-u.workers.dev";
const cfg=JSON.parse(readFileSync("wrangler.registry-staging.local.jsonc","utf8"));
assert.equal(cfg.vars.SSO_ISSUER,issuer);
const client=cfg.vars.REGISTRY_OIDC_CLIENT_ID;
assert.match(client,/^dl_[A-Za-z0-9_-]+$/);
const callback="http://localhost:8765/callback";
const verifier=randomBytes(32).toString("base64url");
const state=randomBytes(32).toString("base64url");
const challenge=createHash("sha256").update(verifier).digest("base64url");
const authorize=new URL(issuer+"/oauth/authorize");
authorize.search=new URLSearchParams({client_id:client,redirect_uri:callback,response_type:"code",scope:"openid profile email",state,code_challenge:challenge,code_challenge_method:"S256"}).toString();
const server=createServer(async(req,res)=>{
 const u=new URL(req.url,callback);
 if(u.pathname!=="/callback"||u.searchParams.get("state")!==state||!u.searchParams.get("code")){res.writeHead(400);res.end("Invalid callback");return;}
 server.close();
 try{
 const r=await fetch(issuer+"/oauth/token",{method:"POST",redirect:"error",signal:AbortSignal.timeout(15000),body:new URLSearchParams({grant_type:"authorization_code",client_id:client,redirect_uri:callback,code:u.searchParams.get("code"),code_verifier:verifier})});
 assert.equal(r.status,200);
 const result=await r.json();
 assert.ok(typeof result.access_token==="string"&&typeof result.id_token==="string");
 res.end("Token exchange passed. Signature and authorization checks remain separate.");
 console.log("PKCE token exchange: PASS");
 }catch{res.writeHead(500);res.end("Token exchange failed");process.exitCode=1;}
});
server.listen(8765,"localhost",()=>console.log("Open in browser (registered loopback callback required): "+authorize));
setTimeout(()=>server.close(),300000).unref();
