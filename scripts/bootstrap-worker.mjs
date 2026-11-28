// Inert bootstrap: no authentication, database access or scheduled work.
export default {async fetch(request,env){
 const origin=env?.SSO_ISSUER;
 const url=new URL(request.url);
 const valid=env?.WORKER==='domislink-sso-confidential-staging'&&typeof origin==='string'&&/^https:\/\/domislink-sso-confidential-staging\.[a-z0-9-]+\.workers\.dev$/.test(origin)&&url.origin===origin;
 const health=valid&&request.method==='GET'&&url.pathname==='/health';
 return Response.json(health?{ok:true,environment:'staging',bootstrap:true,authenticationEnabled:false,executionEnabled:false}:{error:'unavailable'},{status:health?200:503,headers:{'Cache-Control':'no-store'}});
}};
