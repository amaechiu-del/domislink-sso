import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import {readFileSync} from "node:fs";
const source=readFileSync(new URL("../recovered/index.js",import.meta.url),"utf8");
const start=source.indexOf('  if (path === "/admin/clients"');
const end=source.indexOf('  if (path === "/api/whatsapp/config"',start);
assert.ok(start>=0 && end>start);
const handle=vm.runInNewContext("(async function(path,request,env){"+source.slice(start,end)+"})",{URL,json3:(body,status)=>({body,status}),randomToken:()=>"test"});
async function run(body,{path="/admin/clients",key="test-key"}={}){
  let writes=0;
  const env={SSO_ADMIN_API_KEY:"test-key",DB:{prepare:()=>({bind:()=>({run:async()=>{writes++;}})})}};
  const result=await handle(path,new Request("https://example.test"+path,{method:"POST",headers:{Authorization:"Bearer "+key},body:JSON.stringify(body)}),env);
  return {result,writes};
}
const valid={client_name:"Registry",redirect_uris:["https://registry.example.test/callback"],allowed_scopes:["openid"]};
test("administrator required",async()=>{const r=await run(valid,{key:"wrong"});assert.equal(r.result.status,401);assert.equal(r.writes,0);});
test("registration rejects unsafe callback URLs",async()=>{
 for(const uri of ["http://example.test/callback","ftp://localhost/callback","https://user:pass@example.test/callback","https://example.test/callback#fragment"]){
 const r=await run({...valid,redirect_uris:[uri]});assert.equal(r.result.status,400);assert.equal(r.writes,0);
 }
});
test("registration rejects invalid names and scopes",async()=>{
 for(const body of [null,{...valid,client_name:12},{...valid,allowed_scopes:"openid"},{...valid,allowed_scopes:["admin"]}]){
 const r=await run(body);assert.equal(r.result.status,400);assert.equal(r.writes,0);
 }
});
test("valid registration writes one client",async()=>{const r=await run(valid);assert.equal(r.result.status,201);assert.equal(r.writes,1);});
test("unrecognized administrator subpath does not register",async()=>{const r=await run(valid,{path:"/admin/clients/extra"});assert.equal(r.result,undefined);assert.equal(r.writes,0);});
