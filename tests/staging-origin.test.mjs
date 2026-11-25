import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFileSync } from "node:fs";
const source = readFileSync(new URL("../recovered/index.js",import.meta.url),"utf8");
const start = source.indexOf("function allowedOrigin(");
const end = source.indexOf("__name(allowedOrigin",start);
assert.ok(start >= 0 && end > start);
const allowed = vm.runInNewContext(source.slice(start,end)+"\nallowedOrigin",{URL});
const req = origin => new Request("https://example.test",{headers:{Origin:origin}});
test("staging denies production origins by default",()=>{
  assert.equal(allowed(req("https://church.domislink.com"),{APP_ENV:"staging"}),null);
});
test("staging accepts only explicit origins",()=>{
  const env={APP_ENV:"staging",SSO_ALLOWED_ORIGINS:"https://registry.example.test"};
  assert.equal(allowed(req("https://registry.example.test"),env),"https://registry.example.test");
  assert.equal(allowed(req("https://other.domislink.com"),env),null);
});
test("existing production origin behavior remains unchanged",()=>{
  assert.equal(allowed(req("https://church.domislink.com"),{}),"https://church.domislink.com");
});
