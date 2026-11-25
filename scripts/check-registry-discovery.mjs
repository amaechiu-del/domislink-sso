import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
const issuer="https://domislink-sso-registry-staging.amaechi-u.workers.dev";
async function get(path){
 const r=await fetch(issuer+path,{redirect:"error",signal:AbortSignal.timeout(10000),headers:{Accept:"application/json"}});
 assert.equal(r.status,200,path+" HTTP status");
 return r.json();
}
const discovery=await get("/.well-known/openid-configuration");
assert.equal(discovery.issuer,issuer);
for(const [key,path] of Object.entries({authorization_endpoint:"/oauth/authorize",token_endpoint:"/oauth/token",jwks_uri:"/oauth/jwks",userinfo_endpoint:"/oauth/userinfo"})) assert.equal(discovery[key],issuer+path,key);
const jwks=await get("/oauth/jwks");
assert.ok(Array.isArray(jwks.keys));
const keys=jwks.keys.filter(k=>k.kid==="domislink-registry-staging");
assert.equal(keys.length,1);
const key=keys[0];
assert.equal(key.kty,"RSA");
assert.equal(key.alg,"RS256");
for(const field of ["d","p","q","dp","dq","qi","oth"]) assert.ok(!Object.hasOwn(key,field),"Private JWK material present");
const dir=process.env.DOMISLINK_SECRET_DIR;
assert.ok(dir,"Set DOMISLINK_SECRET_DIR");
const expected=createPublicKey(readFileSync(join(dir,"OIDC_PUBLIC_KEY_PEM"))).export({format:"jwk"});
assert.equal(key.n,expected.n);
assert.equal(key.e,expected.e);
console.log("Staging discovery and public signing key: PASS");
