export function validateManifest(m){
 if(!m||typeof m!=="object"||Array.isArray(m))throw Error("Manifest required");
 if(!/^[a-z][a-z0-9-]{1,63}$/.test(m.application_id||""))throw Error("Invalid application ID");
 if(!/^amaechiu-del\/[A-Za-z0-9_.-]+$/.test(m.repository||""))throw Error("Invalid repository");
 if(!["staging","production"].includes(m.environment))throw Error("Invalid environment");
 const origin=new URL(m.origin),callback=new URL(m.redirect_uri);
 if(origin.protocol!=="https:"||origin.href!==origin.origin+"/"||callback.origin!==origin.origin||callback.username||callback.password||callback.hash||callback.pathname==="/")throw Error("Invalid origin or callback");
 if(m.environment==="production"&&!(origin.hostname==="domislink.com"||origin.hostname.endsWith(".domislink.com")))throw Error("Production domain required");
 if(m.environment==="staging"&&!(origin.hostname.endsWith(".workers.dev")&&origin.hostname.includes("staging")))throw Error("Staging domain required");
 if(!Array.isArray(m.scopes)||!m.scopes.includes("openid")||m.scopes.some(s=>!["openid","profile","email","phone"].includes(s)))throw Error("Invalid identity scopes");
 return {application_id:m.application_id,repository:m.repository,environment:m.environment,origin:origin.origin,redirect_uri:callback.href,scopes:[...new Set(m.scopes)]};
}
