import {execFileSync} from "node:child_process";
import {resolve,join} from "node:path";
import {existsSync,mkdirSync,readFileSync,writeFileSync,realpathSync} from "node:fs";
const [target,commit]=process.argv.slice(2);
if(!target||! /^[a-f0-9]{40}$/.test(commit||""))throw Error("Usage: node scripts/install-sso-sdk.mjs APP_ROOT REVIEWED_COMMIT_SHA");
const root=realpathSync(resolve(target));
if(!existsSync(join(root,"package.json")))throw Error("Application package.json required");
const dir=join(root,"vendor","domislink-sso");
const files=["pkce.mjs","application-manifest.mjs"].map(name=>({name,content:execFileSync("git",["show",commit+":sdk/"+name],{encoding:"utf8"})}));
mkdirSync(dir,{recursive:true});
for(const f of files){const path=join(dir,f.name);if(existsSync(path)&&readFileSync(path,"utf8")!==f.content)throw Error("Existing SDK differs; review before updating");}
for(const f of files){const path=join(dir,f.name);if(!existsSync(path))writeFileSync(path,f.content,{flag:"wx"});}
console.log("Pinned SDK copied; application authentication wiring and acceptance tests still required.");
