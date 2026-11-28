// Internal signing primitive only. No public issuance route or implicit user authorization.
export async function issueRunnerToken({subject,issuer,sign,now=Math.floor(Date.now()/1000),ttl=300}){
 if(typeof subject!=='string'||!/^runner_[A-Za-z0-9_-]{16,128}$/.test(subject)||typeof issuer!=='string'||!/^https:\/\/domislink-sso-confidential-staging\.[a-z0-9-]+\.workers\.dev$/.test(issuer)||typeof sign!=='function'||!Number.isSafeInteger(now)||now<0||!Number.isSafeInteger(ttl)||ttl<1||ttl>300)throw Error('Invalid runner signing context');
 const claims={iss:issuer,sub:subject,aud:'domislink-rapid-build-runner',token_use:'access',scope:'rapidbuild:run',iat:now,exp:now+ttl,jti:crypto.randomUUID()};
 return sign(claims);
}
