import assert from "node:assert/strict";
import {readFileSync,writeFileSync} from "node:fs";
import {join} from "node:path";
const input=process.argv[2];
assert.ok(input,"Provide reviewed subject-to-role JSON file");
const grants=JSON.parse(readFileSync(input,"utf8"));
assert.ok(grants && typeof grants==="object" && !Array.isArray(grants));
const entries=Object.entries(grants);
assert.ok(entries.length<=100);
for(const [subject,role] of entries){
 assert.match(subject,/^[A-Za-z0-9_-]{1,160}$/);
 assert.ok(!["__proto__","constructor","prototype"].includes(subject));
 assert.ok(["reader","admin"].includes(role),"Invalid role");
}
const dir=process.env.DOMISLINK_SECRET_DIR;
assert.ok(dir,"Set DOMISLINK_SECRET_DIR");
const target=join(dir,"REGISTRY_ACCESS_GRANTS");
writeFileSync(target,JSON.stringify(Object.fromEntries(entries)),{flag:"wx",mode:0o600});
console.log("Grant file prepared; verify subjects against active staging users before uploading.");
console.log("Readers: "+entries.filter(e=>e[1]==="reader").length);
console.log("Administrators: "+entries.filter(e=>e[1]==="admin").length);
