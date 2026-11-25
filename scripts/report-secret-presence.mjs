import {statSync} from "node:fs";
import {join} from "node:path";
const dir=process.env.DOMISLINK_SECRET_DIR;
if(!dir){console.error("Set DOMISLINK_SECRET_DIR");process.exit(1);}
const names=["OIDC_PRIVATE_KEY_PEM","OIDC_PUBLIC_KEY_PEM","SSO_ADMIN_API_KEY","SSO_INTERNAL_API_KEY","REGISTRY_ACCESS_GRANTS"];
const credentials=names.map(name=>{
 let present=false;
 try{const s=statSync(join(dir,name));present=s.isFile()&&s.size>0;}catch{}
 return {name,present};
});
console.log(JSON.stringify({service:"domislink-sso",environment:"staging",source:"local_files_only",cloudflare_presence:"not_verified",credentials},null,2));
if(credentials.some(c=>!c.present))process.exitCode=2;
