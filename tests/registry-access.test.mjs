import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { randomUUID } from "node:crypto";
const source = readFileSync(new URL("../recovered/index.js", import.meta.url), "utf8");
const start = source.indexOf("async function clientAccessToken(");
const end = source.indexOf("async function jwks(", start);
assert.ok(start >= 0 && end > start);
const issue = vm.runInNewContext(source.slice(start,end) + "\nclientAccessToken", {
  crypto: { randomUUID }, idToken: async (_, claims) => claims,
  adstudioAccessToken: async () => "adstudio-token"
});
const env = { REGISTRY_OIDC_CLIENT_ID: "registry-test", REGISTRY_ACCESS_GRANTS: '{"alice":"reader","bob":"admin"}' };
test("reader receives restricted audience and scope", async () => {
  const token = await issue(env,"registry-test","alice");
  assert.equal(token.aud,"domislink-central-services-registry");
  assert.equal(token.scope,"services:read");
  assert.equal(token.roles.length,0);
  assert.equal(token.exp-token.nbf,900);
});
test("admin receives explicit write scope", async () => {
  const token = await issue(env,"registry-test","bob");
  assert.equal(token.scope,"services:read services:write");
  assert.equal(token.roles[0],"domislink:services:admin");
});
test("missing, malformed and inherited grants fail closed", async () => {
  for (const grants of ["{}", "{", "[]", '{"alice":"owner"}', "null"]) {
    assert.equal(await issue({...env,REGISTRY_ACCESS_GRANTS:grants},"registry-test","alice"),null);
  }
  assert.equal(await issue(env,"registry-test","toString"),null);
  assert.equal(await issue(env,"other-client","bob"),null);
  assert.equal(await issue({},"registry-test","bob"),null);
});
test("AdStudio remains supported", async () => {
  assert.equal(await issue(env,"domislink-adstudio","alice"),"adstudio-token");
});
test("both token exchanges use the scoped helper", () => {
  assert.equal(source.split("const apiToken = await clientAccessToken(env, clientId, user.id);").length-1,2);
});
