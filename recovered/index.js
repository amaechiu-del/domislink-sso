import { authenticateTokenClient } from "../confidential-client.mjs";
import { sendSmsOtp } from "../sms.ts";
import { handleRecovery } from "../recovery.ts";
var __freeze = Object.freeze;
var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __template = (cooked, raw) => __freeze(__defProp(cooked, "raw", { value: __freeze(raw || cooked.slice()) }));

// Reuse the reviewed portable Church password implementation.
import { randomToken, sha256, verifyPassword, hashPassword, readCookie } from "../security.ts";

// src/identity-channels.ts
var EMAIL_OTP_MINUTES = 10;
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
}
__name(json, "json");
function sessionCookie(token) {
  return `dl_sso_session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=1209600`;
}
__name(sessionCookie, "sessionCookie");
async function issueSession(env, userId) {
  const token = randomToken(32), now = /* @__PURE__ */ new Date(), expires = new Date(now.getTime() + 14 * 864e5).toISOString();
  await env.DB.prepare("INSERT INTO sso_sessions(id,token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?,?)").bind(crypto.randomUUID(), await sha256(token), userId, now.toISOString(), expires).run();
  return token;
}
__name(issueSession, "issueSession");
function otpCode() {
  const bytes = crypto.getRandomValues(new Uint32Array(1));
  return String(bytes[0] % 1e6).padStart(6, "0");
}
__name(otpCode, "otpCode");
async function sendEmailOtp(env, email, code) {
  if (!env.RESEND_API_KEY) throw new Error("Email verification is not configured yet.");
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST", redirect: "manual", signal: AbortSignal.timeout(15000),
    headers: { Authorization: "Bearer " + env.RESEND_API_KEY.trim(), "Content-Type": "application/json" },
    body: JSON.stringify({
      from: (env.RESEND_FROM_EMAIL || env.EMAIL_FROM || "DomisLink <no-reply@domislink.com>").trim(),
      to: [email],
      subject: "Your DomisLink verification code",
      text: `Your DomisLink verification code is ${code}. It expires in 10 minutes. If you did not request this code, ignore this email.`,
      html: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:28px;color:#14251f"><p style="font-weight:700;letter-spacing:2px;color:#a5822f">DOMISLINK \xB7 THE DIGITAL EMPIRE</p><h1>Verify your email</h1><p>Use this one-time code to continue securely.</p><p style="font-size:32px;font-weight:700;letter-spacing:8px;padding:18px;background:#f3f5f1;border-radius:12px;text-align:center">${code}</p><p>This code expires in 10 minutes. If you did not request it, ignore this message.</p></div>`
    })
  });
  if (!response.ok) {
    let reason = "unclassified";
    try {
      const payload = await response.json();
      const known = new Set(["validation_error","missing_api_key","restricted_api_key","invalid_api_key","invalid_from_address","invalid_access","invalid_parameter","missing_required_field","monthly_quota_exceeded","daily_quota_exceeded","rate_limit_exceeded","application_error","internal_server_error"]);
      if (known.has(payload?.name)) reason = payload.name;
      // Match a fixed phrase, never expose arbitrary provider text or recipient data.
      if (payload?.message === "API key is invalid") reason = "invalid_api_key";
    } catch { /* An empty/non-JSON rejection still retains its HTTP status. */ }
    console.error("Email provider rejected verification", {provider:"resend",status:response.status,reason});
    throw new Error("Email delivery is unavailable (provider HTTP " + response.status + "; " + reason + ").");
  }
}
__name(sendEmailOtp, "sendEmailOtp");
async function sendPhoneOtp(env, phone, code) {
  return sendSmsOtp(env, phone, code);
}
__name(sendPhoneOtp, "sendPhoneOtp");
function normalizePhone(value) {
  const compact = value.trim().replaceAll(" ", "").replaceAll("(", "").replaceAll(")", "").replaceAll("-", "").replaceAll(".", "");
  if (!compact.startsWith("+") || compact.length < 9 || compact.length > 16 || compact.slice(1).split("").some((char) => char < "0" || char > "9") || compact[1] === "0") return null;
  return compact;
}
__name(normalizePhone, "normalizePhone");
async function claimVerifiedPhone(env, phone, userId, now) {
  await env.DB.prepare("INSERT INTO sso_verified_phones(phone_e164,user_id,verified_at,created_at) VALUES(?,?,?,?) ON CONFLICT(phone_e164) DO NOTHING").bind(phone, userId, now, now).run();
  const owner = await env.DB.prepare("SELECT user_id FROM sso_verified_phones WHERE phone_e164=? LIMIT 1").bind(phone).first();
  if (!owner || owner.user_id !== userId) throw new Error("That phone number is already linked to another DomisLink account.");
}
__name(claimVerifiedPhone, "claimVerifiedPhone");
async function consumeRateLimit(env, key, limit, windowMs, now) {
  const nowIso = now.toISOString();
  const cutoff = new Date(now.getTime() - windowMs).toISOString();
  const expires = new Date(now.getTime() + windowMs).toISOString();
  const row = await env.DB.prepare(`INSERT INTO sso_rate_limits(rate_key,window_started_at,hits,expires_at) VALUES(?,?,1,?)
    ON CONFLICT(rate_key) DO UPDATE SET
      hits=CASE WHEN sso_rate_limits.window_started_at<=? THEN 1 ELSE sso_rate_limits.hits+1 END,
      window_started_at=CASE WHEN sso_rate_limits.window_started_at<=? THEN excluded.window_started_at ELSE sso_rate_limits.window_started_at END,
      expires_at=excluded.expires_at
    RETURNING hits`).bind(key, nowIso, expires, cutoff, cutoff).first();
  return (row?.hits || 0) <= limit;
}
__name(consumeRateLimit, "consumeRateLimit");
async function createOrFindUser(env, channel, destination, fullName) {
  const now = (/* @__PURE__ */ new Date()).toISOString();
  if (channel === "email") {
    const email = destination.toLowerCase();
    let user2 = await env.DB.prepare("SELECT id,email,full_name,status FROM users WHERE email=? LIMIT 1").bind(email).first();
    if (user2 && user2.status !== "active") throw new Error("This DomisLink account is not active. Contact support.");
    if (!user2) {
      const id = crypto.randomUUID();
      await env.DB.prepare("INSERT INTO users(id,email,password_hash,full_name,status,email_verified_at,created_at,updated_at) VALUES(?,?,NULL,?,'active',?,?,?)").bind(id, email, fullName.trim().slice(0, 120) || "DomisLink User", now, now, now).run();
      user2 = { id, email, full_name: fullName.trim().slice(0, 120) || "DomisLink User", status: "active" };
    } else {
      await env.DB.prepare("UPDATE users SET email_verified_at=COALESCE(email_verified_at,?),updated_at=? WHERE id=?").bind(now, now, user2.id).run();
    }
    return user2;
  }
  const phone = destination;
  let user = await env.DB.prepare("SELECT u.id,u.email,u.full_name,u.phone,u.status FROM sso_verified_phones p JOIN users u ON u.id=p.user_id WHERE p.phone_e164=? LIMIT 1").bind(phone).first();
  if (!user) user = await env.DB.prepare("SELECT id,email,full_name,phone,status FROM users WHERE phone=? LIMIT 1").bind(phone).first();
  if (user && user.status !== "active") throw new Error("This DomisLink account is not active. Contact support.");
  if (!user) {
    const syntheticEmail = "phone." + (await sha256(phone)).slice(0, 28) + "@phone.domislink.invalid";
    const id = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO users(id,email,password_hash,full_name,phone,status,created_at,updated_at) VALUES(?,?,NULL,?,?,?,'active',?,?)").bind(id, syntheticEmail, fullName.trim().slice(0, 120) || "DomisLink User", phone, now, now).run();
    user = { id, email: syntheticEmail, full_name: fullName.trim().slice(0, 120) || "DomisLink User", phone, status: "active" };
  }
  await claimVerifiedPhone(env, phone, user.id, now);
  if (user.phone !== phone) {
    await env.DB.prepare("UPDATE users SET phone=?,updated_at=? WHERE id=?").bind(phone, now, user.id).run();
  }
  await env.DB.prepare("DELETE FROM sso_verified_phones WHERE user_id=? AND phone_e164<>?").bind(user.id, phone).run();
  return user;
}
__name(createOrFindUser, "createOrFindUser");
async function startOtp(request, env, channel) {
  const body = await request.json().catch(() => ({}));
  const emailInput = typeof body?.email === "string" ? body.email : "";
  const phoneInput = typeof body?.phone === "string" ? body.phone : "";
  const fullName = typeof body?.full_name === "string" ? body.full_name : "";
  const destination = channel === "email" ? emailInput.trim().toLowerCase() : normalizePhone(phoneInput) || "";
  if (channel === "email" && (destination.length > 254 || destination.split("@").length !== 2 || !destination.split("@")[0] || !destination.split("@")[1]?.includes("."))) return json({ error: "Enter a valid email address." }, 400);
  if (channel === "phone" && !destination) return json({ error: "Enter a phone number in international format, such as +2348012345678." }, 400);
  const now = /* @__PURE__ */ new Date(), nowIso = now.toISOString(), destinationHash = await sha256(destination);
  const ipHash = await sha256(request.headers.get("CF-Connecting-IP") || "unknown");
  if (!await consumeRateLimit(env, await sha256("sso:otp:ip:hour:" + ipHash), 20, 60 * 6e4, now)) {
    return json({ error: "Too many verification requests from this network. Try again later." }, 429);
  }
  if (!await consumeRateLimit(env, await sha256("sso:otp:destination:minute:" + channel + ":" + destinationHash), 1, 6e4, now)) {
    return json({ error: "Please wait 60 seconds before requesting another code." }, 429);
  }
  if (!await consumeRateLimit(env, await sha256("sso:otp:destination:hour:" + channel + ":" + destinationHash), 5, 60 * 6e4, now)) {
    return json({ error: "Too many verification attempts. Try again later." }, 429);
  }
  const code = otpCode(), id = crypto.randomUUID(), expires = new Date(now.getTime() + EMAIL_OTP_MINUTES * 6e4).toISOString();
  await env.DB.prepare("INSERT INTO sso_verification_challenges(id,channel,purpose,destination_hash,ip_hash,code_hash,attempts,created_at,expires_at) VALUES(?,?, 'signin',?,?,?,0,?,?)").bind(id, channel, destinationHash, ipHash, await sha256(id + "." + code), nowIso, expires).run();
  try {
    if (channel === "email") await sendEmailOtp(env, destination, code);
    else await sendPhoneOtp(env, destination, code);
  } catch (error) {
    await env.DB.prepare("UPDATE sso_verification_challenges SET consumed_at=? WHERE id=?").bind(nowIso, id).run();
    return json({ error: error instanceof Error ? error.message : "Unable to send verification code." }, 503);
  }
  return json({ ok: true, challenge_id: id, expires_in: EMAIL_OTP_MINUTES * 60, destination_hint: channel === "email" ? destination.replace(/^(.).+(@.*)$/, "$1\u2022\u2022\u2022\u2022$2") : destination.slice(0, 4) + "\u2022\u2022\u2022\u2022" + destination.slice(-3) });
}
__name(startOtp, "startOtp");
async function verifyOtp(request, env, channel) {
  const body = await request.json().catch(() => ({}));
  const emailInput = typeof body?.email === "string" ? body.email : "";
  const phoneInput = typeof body?.phone === "string" ? body.phone : "";
  const code = typeof body?.code === "string" ? body.code.trim() : "";
  const fullName = typeof body?.full_name === "string" ? body.full_name : "";
  const destination = channel === "email" ? emailInput.trim().toLowerCase() : normalizePhone(phoneInput) || "";
  if (!destination || code.length !== 6 || [...code].some((char) => char < "0" || char > "9")) return json({ error: "Enter the six-digit verification code." }, 400);
  const destinationHash = await sha256(destination), now = /* @__PURE__ */ new Date(), nowIso = now.toISOString();
  const challenge = await env.DB.prepare("SELECT id,code_hash FROM sso_verification_challenges WHERE channel=? AND purpose='signin' AND destination_hash=? AND consumed_at IS NULL AND expires_at>? ORDER BY created_at DESC LIMIT 1").bind(channel, destinationHash, nowIso).first();
  if (!challenge) return json({ error: "The code is invalid or expired. Request a new code." }, 400);
  const attempt = await env.DB.prepare("UPDATE sso_verification_challenges SET attempts=attempts+1 WHERE id=? AND attempts<5 AND consumed_at IS NULL RETURNING attempts").bind(challenge.id).first();
  if (!attempt) return json({ error: "Too many attempts. Request a new verification code." }, 429);
  if (await sha256(challenge.id + "." + code) !== challenge.code_hash) return json({ error: "The code is incorrect. Please try again." }, 400);
  const consumed = await env.DB.prepare("UPDATE sso_verification_challenges SET consumed_at=? WHERE id=? AND consumed_at IS NULL AND expires_at>? RETURNING id").bind(nowIso, challenge.id, nowIso).first();
  if (!consumed) return json({ error: "This verification code has already been used. Request a new code." }, 409);
  let user;
  try {
    const sessionToken = readCookie(request.headers.get("Cookie") || void 0, "dl_sso_session");
    const activeSession = sessionToken ? await env.DB.prepare("SELECT u.id,u.email,u.full_name,u.status FROM sso_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.status='active' LIMIT 1").bind(await sha256(sessionToken), nowIso).first() : null;
    if (activeSession) {
      if (channel === "email") {
        const conflict = await env.DB.prepare("SELECT id FROM users WHERE email=? AND id<>? LIMIT 1").bind(destination, activeSession.id).first();
        if (conflict) throw new Error("That email is already linked to another DomisLink account.");
        await env.DB.prepare("UPDATE users SET email=?,email_verified_at=?,updated_at=? WHERE id=?").bind(destination, nowIso, nowIso, activeSession.id).run();
        user = { ...activeSession, email: destination };
      } else {
        const conflict = await env.DB.prepare("SELECT id FROM users WHERE phone=? AND id<>? LIMIT 1").bind(destination, activeSession.id).first();
        if (conflict) throw new Error("That phone number is already linked to another DomisLink account.");
        await claimVerifiedPhone(env, destination, activeSession.id, nowIso);
        await env.DB.prepare("UPDATE users SET phone=?,updated_at=? WHERE id=?").bind(destination, nowIso, activeSession.id).run();
        await env.DB.prepare("DELETE FROM sso_verified_phones WHERE user_id=? AND phone_e164<>?").bind(activeSession.id, destination).run();
        user = { ...activeSession, phone: destination };
      }
    } else {
      user = await createOrFindUser(env, channel, destination, fullName);
    }
  } catch (error) {
    return json({ error: error instanceof Error ? error.message : "Unable to create your account." }, 409);
  }
  const token = await issueSession(env, user.id);
  const headers = new Headers({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "Set-Cookie": sessionCookie(token) });
  return new Response(JSON.stringify({ ok: true, authenticated: true, user: { id: user.id, email: channel === "email" ? user.email : null, phone: channel === "phone" ? destination : null, fullName: user.full_name }, next: "register_passkey_optional" }), { headers });
}
__name(verifyOtp, "verifyOtp");
async function handleIdentityChannel(request, env, path) {
  if (path === "/auth/email/start" && request.method === "POST") return startOtp(request, env, "email");
  if (path === "/auth/email/verify" && request.method === "POST") return verifyOtp(request, env, "email");
  if (path === "/auth/phone/start" && request.method === "POST") return startOtp(request, env, "phone");
  if (path === "/auth/phone/verify" && request.method === "POST") return verifyOtp(request, env, "phone");
  return null;
}
__name(handleIdentityChannel, "handleIdentityChannel");

// src/passkeys.ts
var enc = new TextEncoder();
function b64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
__name(b64url, "b64url");
function fromB64url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}
__name(fromB64url, "fromB64url");
function json2(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers } });
}
__name(json2, "json");
function rpId(env) {
  return env.WEBAUTHN_RP_ID || "domislink.com";
}
__name(rpId, "rpId");
function setSessionCookie(token) {
  return `dl_sso_session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=1209600`;
}
__name(setSessionCookie, "setSessionCookie");
async function getSession(request, env) {
  const token = readCookie(request.headers.get("Cookie") || void 0, "dl_sso_session");
  if (!token) return null;
  return env.DB.prepare("SELECT u.id,u.email,u.full_name,u.email_verified_at,p.phone_e164 AS verified_phone FROM sso_sessions s JOIN users u ON u.id=s.user_id LEFT JOIN sso_verified_phones p ON p.user_id=u.id AND p.phone_e164=u.phone WHERE s.token_hash=? AND s.expires_at>? AND u.status='active' LIMIT 1").bind(await sha256(token), (/* @__PURE__ */ new Date()).toISOString()).first();
}
__name(getSession, "getSession");
async function issueSession2(env, userId) {
  const token = randomToken(32), now = /* @__PURE__ */ new Date(), expires = new Date(now.getTime() + 14 * 864e5).toISOString();
  await env.DB.prepare("INSERT INTO sso_sessions(id,token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?,?)").bind(crypto.randomUUID(), await sha256(token), userId, now.toISOString(), expires).run();
  return token;
}
__name(issueSession2, "issueSession");
function isDomisLinkOrigin(origin) {
  try {
    const parsed = new URL(origin);
    return parsed.protocol === "https:" && (parsed.hostname === "domislink.com" || parsed.hostname.endsWith(".domislink.com"));
  } catch {
    return false;
  }
}
__name(isDomisLinkOrigin, "isDomisLinkOrigin");
function trustedOrigin(request) {
  return isDomisLinkOrigin(request.headers.get("Origin") || "");
}
__name(trustedOrigin, "trustedOrigin");
function parseClientData(raw, expectedType, challenge, request) {
  const bytes = fromB64url(raw);
  const client = JSON.parse(new TextDecoder().decode(bytes));
  const requestOrigin = request.headers.get("Origin") || "";
  if (client.type !== expectedType || client.challenge !== challenge || !isDomisLinkOrigin(client.origin || "") || client.origin !== requestOrigin || client.crossOrigin === true) {
    throw new Error("WebAuthn client data validation failed.");
  }
  return bytes;
}
__name(parseClientData, "parseClientData");
function readLength(bytes, offset, additional) {
  if (additional < 24) return { length: additional, next: offset };
  if (additional === 24) return { length: bytes[offset], next: offset + 1 };
  if (additional === 25) return { length: bytes[offset] << 8 | bytes[offset + 1], next: offset + 2 };
  if (additional === 26) return { length: new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0), next: offset + 4 };
  throw new Error("Unsupported CBOR length.");
}
__name(readLength, "readLength");
function decodeCbor(bytes, start = 0) {
  if (start >= bytes.length) throw new Error("Truncated CBOR data.");
  const initial = bytes[start], major = initial >> 5, additional = initial & 31;
  if (major === 7) {
    if (additional === 20) return { value: false, offset: start + 1 };
    if (additional === 21) return { value: true, offset: start + 1 };
    if (additional === 22) return { value: null, offset: start + 1 };
  }
  const info = readLength(bytes, start + 1, additional);
  let offset = info.next;
  if (major === 0) return { value: info.length, offset };
  if (major === 1) return { value: -1 - info.length, offset };
  if (major === 2) {
    if (offset + info.length > bytes.length) throw new Error("Truncated CBOR byte string.");
    return { value: bytes.slice(offset, offset + info.length), offset: offset + info.length };
  }
  if (major === 3) return { value: new TextDecoder().decode(bytes.slice(offset, offset + info.length)), offset: offset + info.length };
  if (major === 4) {
    const values = [];
    for (let i = 0; i < info.length; i++) {
      const item = decodeCbor(bytes, offset);
      values.push(item.value);
      offset = item.offset;
    }
    return { value: values, offset };
  }
  if (major === 5) {
    const values = /* @__PURE__ */ new Map();
    for (let i = 0; i < info.length; i++) {
      const key = decodeCbor(bytes, offset), value = decodeCbor(bytes, key.offset);
      values.set(key.value, value.value);
      offset = value.offset;
    }
    return { value: values, offset };
  }
  throw new Error("Unsupported CBOR data.");
}
__name(decodeCbor, "decodeCbor");
function mapValue(map, key) {
  return map.get(key);
}
__name(mapValue, "mapValue");
async function validateAuthenticatorData(authData, env, requireAttested) {
  if (authData.length < 37) throw new Error("Authenticator data is incomplete.");
  const rpHash = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(rpId(env))));
  for (let i = 0; i < 32; i++) if (authData[i] !== rpHash[i]) throw new Error("This passkey belongs to a different relying party.");
  const flags = authData[32];
  if ((flags & 1) === 0 || (flags & 4) === 0) throw new Error("Device presence and user verification are required.");
  const counter = new DataView(authData.buffer, authData.byteOffset + 33, 4).getUint32(0);
  if (requireAttested && (flags & 64) === 0) throw new Error("Passkey attested credential data is missing.");
  return { flags, counter };
}
__name(validateAuthenticatorData, "validateAuthenticatorData");
function jwkFromCose(cose) {
  const kty = mapValue(cose, 1), alg = mapValue(cose, 3);
  if (kty === 2 && alg === -7 && mapValue(cose, -1) === 1) {
    const x = mapValue(cose, -2), y = mapValue(cose, -3);
    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) throw new Error("Unsupported EC passkey key.");
    return { alg: -7, jwk: { kty: "EC", crv: "P-256", x: b64url(x), y: b64url(y), ext: true } };
  }
  if (kty === 3 && alg === -257) {
    const n = mapValue(cose, -1), e = mapValue(cose, -2);
    if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array)) throw new Error("Unsupported RSA passkey key.");
    return { alg: -257, jwk: { kty: "RSA", n: b64url(n), e: b64url(e), alg: "RS256", ext: true } };
  }
  throw new Error("This device's passkey algorithm is not supported. Use a P-256 or RSA passkey.");
}
__name(jwkFromCose, "jwkFromCose");
function derToRaw(signature) {
  if (signature.length === 64) return signature;
  let offset = 0;
  if (signature[offset++] !== 48) throw new Error("Invalid ECDSA signature.");
  const sequenceLength = signature[offset++];
  if (sequenceLength + 2 !== signature.length || signature[offset++] !== 2) throw new Error("Invalid ECDSA signature.");
  const rLength = signature[offset++], r = signature.slice(offset, offset + rLength);
  offset += rLength;
  if (signature[offset++] !== 2) throw new Error("Invalid ECDSA signature.");
  const sLength = signature[offset++], sv = signature.slice(offset, offset + sLength);
  const out = new Uint8Array(64), rr = r[0] === 0 ? r.slice(1) : r, ss = sv[0] === 0 ? sv.slice(1) : sv;
  if (rr.length > 32 || ss.length > 32) throw new Error("Invalid ECDSA signature size.");
  out.set(rr, 32 - rr.length);
  out.set(ss, 64 - ss.length);
  return out;
}
__name(derToRaw, "derToRaw");
async function verifySignature(publicKeyJson, algorithm, signature, signedData) {
  const jwk = JSON.parse(publicKeyJson);
  if (algorithm === -7) {
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRaw(signature), signedData);
  }
  if (algorithm === -257) {
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, signedData);
  }
  return false;
}
__name(verifySignature, "verifySignature");
async function storeChallenge(env, userId, purpose) {
  const challenge = randomToken(32), now = /* @__PURE__ */ new Date(), expires = new Date(now.getTime() + 5 * 6e4).toISOString();
  await env.DB.prepare("INSERT INTO sso_webauthn_challenges(challenge_hash,user_id,purpose,created_at,expires_at) VALUES(?,?,?,?,?)").bind(await sha256(challenge), userId, purpose, now.toISOString(), expires).run();
  return challenge;
}
__name(storeChallenge, "storeChallenge");
async function consumeChallenge(env, challenge, userId, purpose) {
  const now = (/* @__PURE__ */ new Date()).toISOString();
  return env.DB.prepare("UPDATE sso_webauthn_challenges SET used_at=? WHERE challenge_hash=? AND user_id=? AND purpose=? AND used_at IS NULL AND expires_at>? RETURNING challenge_hash").bind(now, await sha256(challenge), userId, purpose, now).first();
}
__name(consumeChallenge, "consumeChallenge");
async function registerOptions(request, env) {
  const user = await getSession(request, env);
  if (!user || !user.email_verified_at && !user.verified_phone) return json2({ error: "Verify an email address or phone number before registering a passkey." }, 401);
  const challenge = await storeChallenge(env, user.id, "registration");
  const existing = await env.DB.prepare("SELECT credential_id FROM sso_passkeys WHERE user_id=?").bind(user.id).all();
  return json2({
    challenge,
    rp: { id: rpId(env), name: env.WEBAUTHN_RP_NAME || "DomisLink" },
    user: { id: b64url(enc.encode(user.id)), name: user.email_verified_at ? user.email : user.verified_phone || "DomisLink account", displayName: user.full_name },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
    timeout: 12e4,
    attestation: "none",
    authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
    excludeCredentials: existing.results.map((item) => ({ type: "public-key", id: item.credential_id }))
  });
}
__name(registerOptions, "registerOptions");
async function registerVerify(request, env) {
  const user = await getSession(request, env);
  if (!user) return json2({ error: "authentication_required" }, 401);
  const body = await request.json();
  if (!body.rawId || !body.response?.clientDataJSON || !body.response.attestationObject) return json2({ error: "Passkey response is incomplete." }, 400);
  try {
    const clientData = JSON.parse(new TextDecoder().decode(fromB64url(body.response.clientDataJSON)));
    if (!clientData.challenge) throw new Error("Missing registration challenge.");
    parseClientData(body.response.clientDataJSON, "webauthn.create", clientData.challenge, request);
    const challenge = await consumeChallenge(env, clientData.challenge, user.id, "registration");
    if (!challenge) throw new Error("Registration challenge expired or already used.");
    const attestation = decodeCbor(fromB64url(body.response.attestationObject)).value;
    if (!(attestation instanceof Map) || mapValue(attestation, "fmt") !== "none" || !(mapValue(attestation, "authData") instanceof Uint8Array)) throw new Error("Only privacy-preserving none attestation is accepted.");
    const authData = mapValue(attestation, "authData");
    await validateAuthenticatorData(authData, env, true);
    if (authData.length < 55) throw new Error("Passkey credential data is truncated.");
    const credentialLength = authData[53] << 8 | authData[54];
    if (credentialLength < 1 || 55 + credentialLength >= authData.length) throw new Error("Passkey credential identifier is invalid.");
    const credentialId = authData.slice(55, 55 + credentialLength);
    if (b64url(fromB64url(body.rawId)) !== b64url(credentialId)) throw new Error("Passkey credential identifier does not match the attested credential.");
    const coseDecoded = decodeCbor(authData.slice(55 + credentialLength)).value;
    if (!(coseDecoded instanceof Map)) throw new Error("Invalid passkey public key.");
    const key = jwkFromCose(coseDecoded);
    const credentialIdEncoded = b64url(credentialId);
    const transports = JSON.stringify((body.response.transports || []).filter((value) => ["usb", "nfc", "ble", "internal", "hybrid"].includes(value)));
    await env.DB.prepare("INSERT INTO sso_passkeys(credential_id,user_id,public_key_json,algorithm,sign_count,transports_json,device_name,created_at) VALUES(?,?,?,?,0,?,?,?)").bind(credentialIdEncoded, user.id, JSON.stringify(key.jwk), key.alg, transports, (body.deviceName || "This device").slice(0, 80), (/* @__PURE__ */ new Date()).toISOString()).run();
    return json2({ ok: true, credential_id: credentialIdEncoded, device_name: body.deviceName || "This device" }, 201);
  } catch (error) {
    return json2({ error: error instanceof Error ? error.message : "Passkey registration failed." }, 400);
  }
}
__name(registerVerify, "registerVerify");
async function authenticationOptions(_request, env) {
  const challenge = await storeChallenge(env, null, "authentication");
  return json2({ challenge, rpId: rpId(env), timeout: 12e4, userVerification: "required" });
}
__name(authenticationOptions, "authenticationOptions");
async function authenticationVerify(request, env) {
  const body = await request.json();
  if (!body.rawId || !body.response?.clientDataJSON || !body.response.authenticatorData || !body.response.signature) return json2({ error: "Passkey assertion is incomplete." }, 400);
  try {
    const clientData = JSON.parse(new TextDecoder().decode(fromB64url(body.response.clientDataJSON)));
    if (!clientData.challenge) throw new Error("Missing authentication challenge.");
    const challengeHash = await sha256(clientData.challenge), now = (/* @__PURE__ */ new Date()).toISOString();
    const challengeRow = await env.DB.prepare("SELECT user_id FROM sso_webauthn_challenges WHERE challenge_hash=? AND purpose='authentication' AND used_at IS NULL AND expires_at>?").bind(challengeHash, now).first();
    if (!challengeRow) throw new Error("Passkey sign-in challenge expired or invalid.");
    parseClientData(body.response.clientDataJSON, "webauthn.get", clientData.challenge, request);
    const credentialId = b64url(fromB64url(body.rawId));
    const passkey = await env.DB.prepare("SELECT credential_id,user_id,public_key_json,algorithm,sign_count FROM sso_passkeys WHERE credential_id=? LIMIT 1").bind(credentialId).first();
    if (!passkey || challengeRow.user_id && challengeRow.user_id !== passkey.user_id) throw new Error("This passkey is not registered to a valid DomisLink identity.");
    if (body.response.userHandle && b64url(fromB64url(body.response.userHandle)) !== b64url(enc.encode(passkey.user_id))) throw new Error("Passkey user handle does not match the registered account.");
    const authData = fromB64url(body.response.authenticatorData);
    const { counter } = await validateAuthenticatorData(authData, env, false);
    if (passkey.sign_count && counter && counter <= passkey.sign_count) throw new Error("Passkey counter validation failed. Re-register this passkey.");
    const clientHash = new Uint8Array(await crypto.subtle.digest("SHA-256", fromB64url(body.response.clientDataJSON)));
    const signedData = new Uint8Array(authData.length + clientHash.length);
    signedData.set(authData);
    signedData.set(clientHash, authData.length);
    if (!await verifySignature(passkey.public_key_json, passkey.algorithm, fromB64url(body.response.signature), signedData)) throw new Error("Passkey signature verification failed.");
    const used = await env.DB.prepare("UPDATE sso_webauthn_challenges SET used_at=? WHERE challenge_hash=? AND (user_id IS NULL OR user_id=?) AND used_at IS NULL AND expires_at>? RETURNING challenge_hash").bind((/* @__PURE__ */ new Date()).toISOString(), challengeHash, passkey.user_id, (/* @__PURE__ */ new Date()).toISOString()).first();
    if (!used) throw new Error("Passkey challenge was already used.");
    if (counter > passkey.sign_count) {
      const advanced = await env.DB.prepare("UPDATE sso_passkeys SET sign_count=?,last_used_at=? WHERE credential_id=? AND sign_count=? AND sign_count<?").bind(counter, (/* @__PURE__ */ new Date()).toISOString(), credentialId, passkey.sign_count, counter).run();
      if (!advanced.meta.changes) throw new Error("Passkey counter changed during sign-in. Please try again.");
    } else {
      await env.DB.prepare("UPDATE sso_passkeys SET last_used_at=? WHERE credential_id=?").bind((/* @__PURE__ */ new Date()).toISOString(), credentialId).run();
    }
    const token = await issueSession2(env, passkey.user_id);
    return new Response(JSON.stringify({ ok: true, authenticated: true }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "Set-Cookie": setSessionCookie(token) } });
  } catch (error) {
    return json2({ error: error instanceof Error ? error.message : "Passkey sign-in failed." }, 401);
  }
}
__name(authenticationVerify, "authenticationVerify");
async function listPasskeys(request, env) {
  const user = await getSession(request, env);
  if (!user) return json2({ error: "authentication_required" }, 401);
  const result = await env.DB.prepare("SELECT credential_id,device_name,created_at,last_used_at FROM sso_passkeys WHERE user_id=? ORDER BY created_at DESC").bind(user.id).all();
  return json2({ passkeys: result.results });
}
__name(listPasskeys, "listPasskeys");
async function deletePasskey(request, env) {
  const user = await getSession(request, env);
  if (!user) return json2({ error: "authentication_required" }, 401);
  const body = await request.json();
  const count = await env.DB.prepare("SELECT COUNT(*) AS total FROM sso_passkeys WHERE user_id=?").bind(user.id).first();
  if ((count?.total || 0) <= 1 && !user.email_verified_at && !user.verified_phone) return json2({ error: "Verify an email address or phone number before removing your only passkey." }, 409);
  await env.DB.prepare("DELETE FROM sso_passkeys WHERE credential_id=? AND user_id=?").bind(body.credential_id || "", user.id).run();
  return json2({ ok: true });
}
__name(deletePasskey, "deletePasskey");
async function handlePasskey(request, env, path) {
  if ((path.startsWith("/auth/passkeys/") || path === "/auth/passkeys" && request.method === "DELETE") && !trustedOrigin(request)) return json2({ error: "trusted_origin_required" }, 403);
  if (path === "/auth/passkeys/register/options" && request.method === "POST") return registerOptions(request, env);
  if (path === "/auth/passkeys/register/verify" && request.method === "POST") return registerVerify(request, env);
  if (path === "/auth/passkeys/authenticate/options" && request.method === "POST") return authenticationOptions(request, env);
  if (path === "/auth/passkeys/authenticate/verify" && request.method === "POST") return authenticationVerify(request, env);
  if (path === "/auth/passkeys" && request.method === "GET") return listPasskeys(request, env);
  if (path === "/auth/passkeys" && request.method === "DELETE") return deletePasskey(request, env);
  return null;
}
__name(handlePasskey, "handlePasskey");

// src/pwa.ts
var _a;
var identityPwaHtml = String.raw(_a || (_a = __template(['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#10251f"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-title" content="DomisLink ID"><link rel="manifest" href="/manifest.webmanifest"><link rel="icon" href="/icon.svg"><link rel="apple-touch-icon" href="/icon.svg"><title>DomisLink Identity</title><style>\n*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 10% 5%,#25483a,#0b211b 55%,#071710);color:#f6f7f1;font:16px Inter,system-ui,sans-serif;display:grid;place-items:center;padding:22px}.shell{width:min(520px,100%)}.brand{color:#e4c46a;font-size:12px;font-weight:800;letter-spacing:2px;margin-bottom:18px}.card{background:#102b22;border:1px solid #345a49;border-radius:24px;padding:clamp(22px,6vw,36px);box-shadow:0 28px 90px #0006}.mark{width:46px;height:42px;border-radius:14px;background:#e4c46a;color:#10251f;display:grid;place-items:center;font-size:24px;margin-bottom:20px}h1{font-size:clamp(26px,6vw,34px);line-height:1.1;margin:0 0 10px}p{color:#b8c9bf;line-height:1.55}.muted{font-size:13px}.field{display:block;margin:17px 0 7px;font-size:13px;color:#d9e2dc}input{width:100%;padding:14px;border:1px solid #557365;background:#071b15;border-radius:12px;color:#fff;font:inherit;outline:none}input:focus{border-color:#e4c46a;box-shadow:0 0 0 3px #e4c46a22}button{width:100%;padding:14px;border:0;border-radius:12px;margin-top:12px;background:#e4c46a;color:#15241d;font-weight:750;font-size:15px;cursor:pointer}button.secondary{background:#1b3a2e;color:#f2f5ef;border:1px solid #52715f}button:disabled{opacity:.55;cursor:wait}.divider{display:flex;align-items:center;gap:12px;color:#90a89a;font-size:12px;margin:20px 0}.divider:before,.divider:after{content:"";height:1px;background:#355748;flex:1}.notice{padding:12px;border-radius:10px;background:#1a4030;color:#d5ead9;font-size:13px;margin:14px 0}.error{padding:12px;border-radius:10px;background:#48251f;color:#ffd0c7;font-size:13px;margin:14px 0}.hidden{display:none!important}.footer{font-size:12px;color:#91a99b;text-align:center;margin-top:16px}.pill{display:inline-block;padding:5px 9px;background:#1d4333;border-radius:99px;color:#d9ebdd;font-size:11px;margin-bottom:12px}.device{padding:12px;border:1px solid #456653;border-radius:12px;margin:9px 0;display:flex;justify-content:space-between;gap:12px;font-size:13px}.device button{width:auto;margin:0;padding:8px 12px;font-size:12px}.status{font-size:13px;min-height:20px;margin-top:12px}@media(max-width:380px){.split{grid-template-columns:1fr}}\n</style></head><body><main class="shell"><div class="brand">DOMISLINK \xB7 THE DIGITAL EMPIRE</div><section class="card"><div class="mark">\u265B</div><div id="authView"><span class="pill">UNIVERSAL IDENTITY</span><h1>One identity.<br>Every DomisLink app.</h1><p>Register or sign in securely with your email, phone or device passkey.</p><button id="installBtn" class="secondary hidden">Install DomisLink Identity</button>\n<label class="field" for="email">Email address</label><input id="email" type="email" autocomplete="email" placeholder="you@example.com"><input id="fullName" autocomplete="name" placeholder="Full name (for new accounts)" style="margin-top:10px"><button id="emailStart">Continue with email</button>\n<div class="divider">OR USE YOUR PHONE</div><label class="field" for="phone">Phone number (international format)</label><input id="phone" type="tel" autocomplete="tel" placeholder="+2348012345678"><button id="phoneStart" class="secondary">Continue with phone</button>\n<div class="divider">ALREADY HAVE A PASSKEY?</div><button id="passkeyLogin" class="secondary">Sign in with fingerprint / Face ID / passkey</button>\n<a href="/forgot-password" style="display:block;text-align:center;margin-top:14px;color:#e4c46a;font-size:13px;text-decoration:none">Forgot password?</a>\n<div id="otpPanel" class="hidden"><div class="divider">VERIFY YOUR CONTACT</div><p id="otpHint">Enter the six-digit code sent to you.</p><label class="field" for="otp">Verification code</label><input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="000000"><button id="verifyOtp">Verify and continue</button></div></div>\n<div id="accountView" class="hidden"><span class="pill">SECURE ACCOUNT</span><h1 id="welcome">Welcome to DomisLink</h1><p id="accountInfo">Your DomisLink identity is active on this device.</p><button id="linkContact" class="secondary">Add or verify another email / phone</button><button id="addPasskey">Enable fingerprint / Face ID</button><h3 style="font-size:16px;margin-top:24px">Your passkeys</h3><div id="passkeyList"></div><button id="logout" class="secondary">Sign out</button></div><div id="status" class="status" role="status" aria-live="polite"></div></section><p class="footer">Your fingerprint or face data stays on your device. DomisLink receives only a cryptographic passkey. On iPhone or iPad, use Share \u2192 Add to Home Screen to install.</p></main>\n<script>\nconst $=id=>document.getElementById(id);let channel="email",destination="",deferredInstall=null,returnTo=new URLSearchParams(location.search).get("return_to")||"";\nconst b64bytes=s=>{const x=s.replace(/-/g,"+").replace(/_/g,"/");const b=atob(x+"=".repeat((4-x.length%4)%4));return Uint8Array.from(b,c=>c.charCodeAt(0));};\nconst b64=s=>{const a=new Uint8Array(s);let b="";a.forEach(v=>b+=String.fromCharCode(v));return btoa(b).replace(/=/g,"").replace(/+/g,"-").replace(///g,"_");};\nfunction status(message,error=false){$("status").textContent=message;$("status").className="status "+(error?"error":"notice");}\nasync function post(path,data={}){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)});const j=await r.json().catch(()=>({error:"Unexpected server response."}));if(!r.ok)throw new Error(j.error||"Request failed.");return j;}\nfunction continueToProduct(){if(returnTo.startsWith("/oauth/authorize?")&&!returnTo.includes("#"))location.assign(returnTo);}\nasync function requestOtp(which){channel=which;destination=which==="email"?$("email").value.trim().toLowerCase():$("phone").value.trim();const name=$("fullName").value.trim();if(!destination)throw new Error(which==="email"?"Enter your email address.":"Enter your phone number with country code.");const result=await post("/auth/"+which+"/start",which==="email"?{email:destination,full_name:name}:{phone:destination,full_name:name});$("otpPanel").classList.remove("hidden");$("otpHint").textContent="We sent a six-digit verification code to "+result.destination_hint+". It expires in 10 minutes.";$("otp").focus();status("Verification code sent.");}\nasync function verifyOtp(){const result=await post("/auth/"+channel+"/verify",channel==="email"?{email:destination,code:$("otp").value,full_name:$("fullName").value}:{phone:destination,code:$("otp").value,full_name:$("fullName").value});if(!result.authenticated)throw new Error("Verification was not completed.");continueToProduct();await showAccount(result.user);}\nfunction bufferOptions(options,registration){options.challenge=b64bytes(options.challenge);if(registration){options.user.id=b64bytes(options.user.id);options.excludeCredentials=(options.excludeCredentials||[]).map(c=>({...c,id:b64bytes(c.id)}));}else{options.allowCredentials=(options.allowCredentials||[]).map(c=>({...c,id:b64bytes(c.id)}));}return options;}\nasync function addPasskey(){if(!window.PublicKeyCredential||!navigator.credentials)throw new Error("This browser does not support device passkeys.");const options=await post("/auth/passkeys/register/options");const publicKey=bufferOptions(options,true);const credential=await navigator.credentials.create({publicKey});if(!credential)throw new Error("Passkey registration was cancelled.");const response=credential.response;const result=await post("/auth/passkeys/register/verify",{rawId:b64(credential.rawId),response:{clientDataJSON:b64(response.clientDataJSON),attestationObject:b64(response.attestationObject),transports:response.getTransports?response.getTransports():[]},deviceName:navigator.platform||"This device"});status("Passkey added. You can now use fingerprint, Face ID or your device screen lock.");await loadPasskeys();}\nasync function passkeyLogin(){const options=await post("/auth/passkeys/authenticate/options",{});const publicKey={challenge:b64bytes(options.challenge),rpId:options.rpId,timeout:options.timeout,userVerification:options.userVerification};const credential=await navigator.credentials.get({publicKey});if(!credential)throw new Error("Passkey sign-in was cancelled.");const response=credential.response;await post("/auth/passkeys/authenticate/verify",{rawId:b64(credential.rawId),response:{clientDataJSON:b64(response.clientDataJSON),authenticatorData:b64(response.authenticatorData),signature:b64(response.signature),userHandle:response.userHandle?b64(response.userHandle):null}});continueToProduct();await showAccount();}\nasync function loadPasskeys(){const r=await fetch("/auth/passkeys",{credentials:"same-origin",cache:"no-store"});if(!r.ok)return;const data=await r.json();$("passkeyList").innerHTML="";(data.passkeys||[]).forEach(item=>{const row=document.createElement("div");row.className="device";const label=document.createElement("span");label.textContent=(item.device_name||"Passkey")+" \xB7 added "+new Date(item.created_at).toLocaleDateString();const button=document.createElement("button");button.textContent="Remove";button.className="secondary";button.onclick=async()=>{try{await deletePasskey(item.credential_id);}catch(e){status(e.message,true);}};row.append(label,button);$("passkeyList").append(row);});if(!(data.passkeys||[]).length)$("passkeyList").textContent="No passkeys registered yet.";}\nasync function deletePasskey(id){const r=await fetch("/auth/passkeys",{method:"DELETE",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({credential_id:id})});const j=await r.json();if(!r.ok)throw new Error(j.error||"Unable to remove passkey.");await loadPasskeys();status("Passkey removed.");}\nasync function showAccount(user){$("authView").classList.add("hidden");$("accountView").classList.remove("hidden");$("welcome").textContent="Welcome, "+(user?.fullName||"DomisLink user");$("accountInfo").textContent="Your verified DomisLink identity is ready for connected applications.";await loadPasskeys();}\nasync function checkSession(){const r=await fetch("/auth/session",{credentials:"same-origin",cache:"no-store"});if(r.ok){const j=await r.json();if(returnTo.startsWith("/oauth/authorize?"))continueToProduct();await showAccount(j.user);}}\nfunction run(id,fn){$(id).addEventListener("click",async()=>{try{status("Please wait\u2026");await fn();}catch(e){status(e instanceof Error?e.message:"Something went wrong.",true);}});}\nrun("emailStart",()=>requestOtp("email"));run("phoneStart",()=>requestOtp("phone"));run("verifyOtp",verifyOtp);run("passkeyLogin",passkeyLogin);run("addPasskey",addPasskey);$("linkContact").addEventListener("click",()=>{$("accountView").classList.add("hidden");$("authView").classList.remove("hidden");$("otpPanel").classList.add("hidden");status("Verify an additional email address or phone number to link it to this same account.");});\n$("logout").addEventListener("click",async()=>{await fetch("/logout",{method:"POST",credentials:"same-origin"});$("accountView").classList.add("hidden");$("authView").classList.remove("hidden");$("otpPanel").classList.add("hidden");status("You have signed out.");});\nwindow.addEventListener("beforeinstallprompt",event=>{event.preventDefault();deferredInstall=event;$("installBtn").classList.remove("hidden");});\n$("installBtn").addEventListener("click",async()=>{if(!deferredInstall)return;deferredInstall.prompt();await deferredInstall.userChoice;deferredInstall=null;$("installBtn").classList.add("hidden");});\nif("serviceWorker" in navigator)navigator.serviceWorker.register("/sw.js").catch(()=>{});\ncheckSession().catch(()=>{});\n<\/script></body></html>'], ['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#10251f"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-title" content="DomisLink ID"><link rel="manifest" href="/manifest.webmanifest"><link rel="icon" href="/icon.svg"><link rel="apple-touch-icon" href="/icon.svg"><title>DomisLink Identity</title><style>\n*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 10% 5%,#25483a,#0b211b 55%,#071710);color:#f6f7f1;font:16px Inter,system-ui,sans-serif;display:grid;place-items:center;padding:22px}.shell{width:min(520px,100%)}.brand{color:#e4c46a;font-size:12px;font-weight:800;letter-spacing:2px;margin-bottom:18px}.card{background:#102b22;border:1px solid #345a49;border-radius:24px;padding:clamp(22px,6vw,36px);box-shadow:0 28px 90px #0006}.mark{width:46px;height:42px;border-radius:14px;background:#e4c46a;color:#10251f;display:grid;place-items:center;font-size:24px;margin-bottom:20px}h1{font-size:clamp(26px,6vw,34px);line-height:1.1;margin:0 0 10px}p{color:#b8c9bf;line-height:1.55}.muted{font-size:13px}.field{display:block;margin:17px 0 7px;font-size:13px;color:#d9e2dc}input{width:100%;padding:14px;border:1px solid #557365;background:#071b15;border-radius:12px;color:#fff;font:inherit;outline:none}input:focus{border-color:#e4c46a;box-shadow:0 0 0 3px #e4c46a22}button{width:100%;padding:14px;border:0;border-radius:12px;margin-top:12px;background:#e4c46a;color:#15241d;font-weight:750;font-size:15px;cursor:pointer}button.secondary{background:#1b3a2e;color:#f2f5ef;border:1px solid #52715f}button:disabled{opacity:.55;cursor:wait}.divider{display:flex;align-items:center;gap:12px;color:#90a89a;font-size:12px;margin:20px 0}.divider:before,.divider:after{content:"";height:1px;background:#355748;flex:1}.notice{padding:12px;border-radius:10px;background:#1a4030;color:#d5ead9;font-size:13px;margin:14px 0}.error{padding:12px;border-radius:10px;background:#48251f;color:#ffd0c7;font-size:13px;margin:14px 0}.hidden{display:none!important}.footer{font-size:12px;color:#91a99b;text-align:center;margin-top:16px}.pill{display:inline-block;padding:5px 9px;background:#1d4333;border-radius:99px;color:#d9ebdd;font-size:11px;margin-bottom:12px}.device{padding:12px;border:1px solid #456653;border-radius:12px;margin:9px 0;display:flex;justify-content:space-between;gap:12px;font-size:13px}.device button{width:auto;margin:0;padding:8px 12px;font-size:12px}.status{font-size:13px;min-height:20px;margin-top:12px}@media(max-width:380px){.split{grid-template-columns:1fr}}\n</style></head><body><main class="shell"><div class="brand">DOMISLINK \xB7 THE DIGITAL EMPIRE</div><section class="card"><div class="mark">\u265B</div><div id="authView"><span class="pill">UNIVERSAL IDENTITY</span><h1>One identity.<br>Every DomisLink app.</h1><p>Register or sign in securely with your email, phone or device passkey.</p><button id="installBtn" class="secondary hidden">Install DomisLink Identity</button>\n<label class="field" for="email">Email address</label><input id="email" type="email" autocomplete="email" placeholder="you@example.com"><input id="fullName" autocomplete="name" placeholder="Full name (for new accounts)" style="margin-top:10px"><button id="emailStart">Continue with email</button>\n<div class="divider">OR USE YOUR PHONE</div><label class="field" for="phone">Phone number (international format)</label><input id="phone" type="tel" autocomplete="tel" placeholder="+2348012345678"><button id="phoneStart" class="secondary">Continue with phone</button>\n<div class="divider">ALREADY HAVE A PASSKEY?</div><button id="passkeyLogin" class="secondary">Sign in with fingerprint / Face ID / passkey</button>\n<div id="otpPanel" class="hidden"><div class="divider">VERIFY YOUR CONTACT</div><p id="otpHint">Enter the six-digit code sent to you.</p><label class="field" for="otp">Verification code</label><input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="000000"><button id="verifyOtp">Verify and continue</button></div></div>\n<div id="accountView" class="hidden"><span class="pill">SECURE ACCOUNT</span><h1 id="welcome">Welcome to DomisLink</h1><p id="accountInfo">Your DomisLink identity is active on this device.</p><button id="linkContact" class="secondary">Add or verify another email / phone</button><button id="addPasskey">Enable fingerprint / Face ID</button><h3 style="font-size:16px;margin-top:24px">Your passkeys</h3><div id="passkeyList"></div><button id="logout" class="secondary">Sign out</button></div><div id="status" class="status" role="status" aria-live="polite"></div></section><p class="footer">Your fingerprint or face data stays on your device. DomisLink receives only a cryptographic passkey. On iPhone or iPad, use Share \u2192 Add to Home Screen to install.</p></main>\n<script>\nconst $=id=>document.getElementById(id);let channel="email",destination="",deferredInstall=null,returnTo=new URLSearchParams(location.search).get("return_to")||"";\nconst b64bytes=s=>{const x=s.replace(/-/g,"+").replace(/_/g,"/");const b=atob(x+"=".repeat((4-x.length%4)%4));return Uint8Array.from(b,c=>c.charCodeAt(0));};\nconst b64=s=>{const a=new Uint8Array(s);let b="";a.forEach(v=>b+=String.fromCharCode(v));return btoa(b).replace(/=/g,"").replace(/\\+/g,"-").replace(/\\//g,"_");};\nfunction status(message,error=false){$("status").textContent=message;$("status").className="status "+(error?"error":"notice");}\nasync function post(path,data={}){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)});const j=await r.json().catch(()=>({error:"Unexpected server response."}));if(!r.ok)throw new Error(j.error||"Request failed.");return j;}\nfunction continueToProduct(){if(returnTo.startsWith("/oauth/authorize?")&&!returnTo.includes("#"))location.assign(returnTo);}\nasync function requestOtp(which){channel=which;destination=which==="email"?$("email").value.trim().toLowerCase():$("phone").value.trim();const name=$("fullName").value.trim();if(!destination)throw new Error(which==="email"?"Enter your email address.":"Enter your phone number with country code.");const result=await post("/auth/"+which+"/start",which==="email"?{email:destination,full_name:name}:{phone:destination,full_name:name});$("otpPanel").classList.remove("hidden");$("otpHint").textContent="We sent a six-digit verification code to "+result.destination_hint+". It expires in 10 minutes.";$("otp").focus();status("Verification code sent.");}\nasync function verifyOtp(){const result=await post("/auth/"+channel+"/verify",channel==="email"?{email:destination,code:$("otp").value,full_name:$("fullName").value}:{phone:destination,code:$("otp").value,full_name:$("fullName").value});if(!result.authenticated)throw new Error("Verification was not completed.");continueToProduct();await showAccount(result.user);}\nfunction bufferOptions(options,registration){options.challenge=b64bytes(options.challenge);if(registration){options.user.id=b64bytes(options.user.id);options.excludeCredentials=(options.excludeCredentials||[]).map(c=>({...c,id:b64bytes(c.id)}));}else{options.allowCredentials=(options.allowCredentials||[]).map(c=>({...c,id:b64bytes(c.id)}));}return options;}\nasync function addPasskey(){if(!window.PublicKeyCredential||!navigator.credentials)throw new Error("This browser does not support device passkeys.");const options=await post("/auth/passkeys/register/options");const publicKey=bufferOptions(options,true);const credential=await navigator.credentials.create({publicKey});if(!credential)throw new Error("Passkey registration was cancelled.");const response=credential.response;const result=await post("/auth/passkeys/register/verify",{rawId:b64(credential.rawId),response:{clientDataJSON:b64(response.clientDataJSON),attestationObject:b64(response.attestationObject),transports:response.getTransports?response.getTransports():[]},deviceName:navigator.platform||"This device"});status("Passkey added. You can now use fingerprint, Face ID or your device screen lock.");await loadPasskeys();}\nasync function passkeyLogin(){const options=await post("/auth/passkeys/authenticate/options",{});const publicKey={challenge:b64bytes(options.challenge),rpId:options.rpId,timeout:options.timeout,userVerification:options.userVerification};const credential=await navigator.credentials.get({publicKey});if(!credential)throw new Error("Passkey sign-in was cancelled.");const response=credential.response;await post("/auth/passkeys/authenticate/verify",{rawId:b64(credential.rawId),response:{clientDataJSON:b64(response.clientDataJSON),authenticatorData:b64(response.authenticatorData),signature:b64(response.signature),userHandle:response.userHandle?b64(response.userHandle):null}});continueToProduct();await showAccount();}\nasync function loadPasskeys(){const r=await fetch("/auth/passkeys",{credentials:"same-origin",cache:"no-store"});if(!r.ok)return;const data=await r.json();$("passkeyList").innerHTML="";(data.passkeys||[]).forEach(item=>{const row=document.createElement("div");row.className="device";const label=document.createElement("span");label.textContent=(item.device_name||"Passkey")+" \xB7 added "+new Date(item.created_at).toLocaleDateString();const button=document.createElement("button");button.textContent="Remove";button.className="secondary";button.onclick=async()=>{try{await deletePasskey(item.credential_id);}catch(e){status(e.message,true);}};row.append(label,button);$("passkeyList").append(row);});if(!(data.passkeys||[]).length)$("passkeyList").textContent="No passkeys registered yet.";}\nasync function deletePasskey(id){const r=await fetch("/auth/passkeys",{method:"DELETE",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({credential_id:id})});const j=await r.json();if(!r.ok)throw new Error(j.error||"Unable to remove passkey.");await loadPasskeys();status("Passkey removed.");}\nasync function showAccount(user){$("authView").classList.add("hidden");$("accountView").classList.remove("hidden");$("welcome").textContent="Welcome, "+(user?.fullName||"DomisLink user");$("accountInfo").textContent="Your verified DomisLink identity is ready for connected applications.";await loadPasskeys();}\nasync function checkSession(){const r=await fetch("/auth/session",{credentials:"same-origin",cache:"no-store"});if(r.ok){const j=await r.json();if(returnTo.startsWith("/oauth/authorize?"))continueToProduct();await showAccount(j.user);}}\nfunction run(id,fn){$(id).addEventListener("click",async()=>{try{status("Please wait\u2026");await fn();}catch(e){status(e instanceof Error?e.message:"Something went wrong.",true);}});}\nrun("emailStart",()=>requestOtp("email"));run("phoneStart",()=>requestOtp("phone"));run("verifyOtp",verifyOtp);run("passkeyLogin",passkeyLogin);run("addPasskey",addPasskey);$("linkContact").addEventListener("click",()=>{$("accountView").classList.add("hidden");$("authView").classList.remove("hidden");$("otpPanel").classList.add("hidden");status("Verify an additional email address or phone number to link it to this same account.");});\n$("logout").addEventListener("click",async()=>{await fetch("/logout",{method:"POST",credentials:"same-origin"});$("accountView").classList.add("hidden");$("authView").classList.remove("hidden");$("otpPanel").classList.add("hidden");status("You have signed out.");});\nwindow.addEventListener("beforeinstallprompt",event=>{event.preventDefault();deferredInstall=event;$("installBtn").classList.remove("hidden");});\n$("installBtn").addEventListener("click",async()=>{if(!deferredInstall)return;deferredInstall.prompt();await deferredInstall.userChoice;deferredInstall=null;$("installBtn").classList.add("hidden");});\nif("serviceWorker" in navigator)navigator.serviceWorker.register("/sw.js").catch(()=>{});\ncheckSession().catch(()=>{});\n<\/script></body></html>'])));
var identityManifest = {
  id: "/",
  name: "DomisLink Universal Identity",
  short_name: "DomisLink ID",
  description: "One secure identity for every DomisLink application.",
  start_url: "/",
  scope: "/",
  display: "standalone",
  display_override: ["standalone", "minimal-ui"],
  background_color: "#0b211b",
  theme_color: "#10251f",
  icons: [{ src: "/icon.svg", sizes: "any", type: "image/svg+xml", purpose: "any maskable" }]
};
var identityServiceWorker = `const CACHE="domislink-identity-shell-v1";
self.addEventListener("install",e=>e.waitUntil(caches.open(CACHE).then(c=>c.add("/"))));
self.addEventListener("activate",e=>e.waitUntil((async()=>{for(const k of await caches.keys())if(k.startsWith("domislink-identity-")&&k!==CACHE)await caches.delete(k);await self.clients.claim();})()));
self.addEventListener("fetch",e=>{const r=e.request,u=new URL(r.url);if(r.method!=="GET"||u.origin!==self.location.origin||u.pathname.startsWith("/auth/")||u.pathname.startsWith("/oauth/")||u.pathname.startsWith("/api/"))return;if(r.mode==="navigate")e.respondWith(fetch(r).catch(()=>caches.match("/")));});
`;
var identityIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="112" fill="#10251f"/><path d="M76 150 172 236 256 72 340 236 436 150 388 420H124L76 150Z" fill="#e4c46a"/><path d="M132 355h248" stroke="#fff2c4" stroke-width="18" stroke-linecap="round"/></svg>`;

// src/index.ts
var enc2 = new TextEncoder();
var ISSUER_DEFAULT = "https://sso.domislink.com";
var SSO_SESSION_SECONDS = 60 * 60 * 24 * 14;
var ACCESS_SECONDS = 60 * 60;
var REFRESH_SECONDS = 60 * 60 * 24 * 30;
var GRAPH_DEFAULT = "v25.0";
function b64url2(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
__name(b64url2, "b64url");
function fromB64(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}
__name(fromB64, "fromB64");
function json3(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers } });
}
__name(json3, "json");
function issuer(env) {
  return env.SSO_ISSUER || ISSUER_DEFAULT;
}
__name(issuer, "issuer");
function graphVersion(env) {
  return env.META_GRAPH_VERSION || GRAPH_DEFAULT;
}
__name(graphVersion, "graphVersion");
function cookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}
__name(cookie, "cookie");
function clearCookie(name) {
  return `${name}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}
__name(clearCookie, "clearCookie");
function htmlEscape(value) {
  return value.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
__name(htmlEscape, "htmlEscape");
function loginHtml(returnTo, csrf, error = "") {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DomisLink SSO</title><style>
  *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#071d17;color:#f5f5f0;font:16px system-ui}.card{width:min(420px,calc(100% - 32px));padding:32px;border:1px solid #355448;border-radius:22px;background:#0d2a22;box-shadow:0 24px 80px #0005}h1{margin:0 0 8px;font-size:27px}.muted{color:#b6c8bd;font-size:14px}label{display:block;margin:18px 0 7px;font-size:14px}input{width:100%;padding:13px;border-radius:10px;border:1px solid #557267;background:#071d17;color:white;font:inherit}button{margin-top:22px;width:100%;padding:14px;border:0;border-radius:10px;background:#d6b65c;color:#172019;font-weight:700;font-size:15px;cursor:pointer}.error{color:#ffb4a9;background:#48231e;padding:10px;border-radius:8px;margin:16px 0}.brand{color:#e3c66c;font-weight:800;letter-spacing:.08em;font-size:12px;margin-bottom:22px}
  .pwd-wrap{position:relative}input.pwd-input{padding-right:44px}
  .pwd-toggle{position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:15px;color:#b6c8bd;padding:6px 8px;border-radius:6px;transition:background .2s,color .2s;line-height:1}.pwd-toggle:hover{background:rgba(255,255,255,.1);color:#e3c66c}
  @keyframes colorCycle{0%{background:#d6b65c;color:#172019}20%{background:#5cc8a8;color:#071d17}40%{background:#5c9ed6;color:#fff}60%{background:#a85cd6;color:#fff}80%{background:#d65c8a;color:#fff}100%{background:#d6b65c;color:#172019}}
  @keyframes spin{to{transform:rotate(360deg)}}
  .submit-btn{transition:background .3s,color .3s;position:relative;overflow:hidden}
  .submit-btn.loading{animation:colorCycle 1.2s ease-in-out infinite;pointer-events:none}
  .submit-btn .spinner{display:none;width:16px;height:16px;border:2.5px solid rgba(23,32,25,.25);border-top-color:currentColor;border-radius:50%;animation:spin .55s linear infinite;vertical-align:middle;margin-right:8px}
  .submit-btn.loading .spinner{display:inline-block}
  .submit-btn.loading .btn-text{opacity:.85}
  .submit-btn .check{display:none;font-size:16px;vertical-align:middle;margin-right:6px}
  .submit-btn.success .check{display:inline-block}
  </style><main class="card"><div class="brand">DOMISLINK \xC2\xB7 THE DIGITAL EMPIRE</div><h1>Sign in once. Go everywhere.</h1><p class="muted">Use your DomisLink account to continue securely.</p>${error ? `<div class="error">${htmlEscape(error)}</div>` : ""}<form method="post" action="/login" id="loginForm"><input type="hidden" name="return_to" value="${htmlEscape(returnTo)}"><input type="hidden" name="csrf" value="${csrf}"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="username" required><label for="password">Password</label><div class="pwd-wrap"><input id="password" name="password" type="password" class="pwd-input" autocomplete="current-password" required><button type="button" class="pwd-toggle" id="pwdToggle" aria-label="Show password" title="Show password">&#128065;</button></div><button type="submit" class="submit-btn" id="submitBtn"><span class="spinner"></span><span class="check">&#10003;</span><span class="btn-text">Continue to DomisLink</span></button></form><p style="text-align:center"><a style="color:#e3c66c" href="/identity?return_to=${encodeURIComponent(returnTo)}">Use email code or passkey</a></p><p style="text-align:center;margin:16px 0 0"><a href="/forgot-password" style="color:#e3c66c;font-size:13px;text-decoration:none">Forgot password?</a></p><p class="muted" style="margin-top:22px">Your sign-in is protected by DomisLink Universal Identity.</p></main><script>
  (function(){
    var pwd=document.getElementById('password'),toggle=document.getElementById('pwdToggle'),form=document.getElementById('loginForm'),btn=document.getElementById('submitBtn');
    var showing=false;
    toggle.addEventListener('click',function(){
      showing=!showing;
      pwd.type=showing?'text':'password';
      toggle.innerHTML=showing?'&#128064;':'&#128065;';
      toggle.setAttribute('aria-label',showing?'Hide password':'Show password');
      toggle.title=showing?'Hide password':'Show password';
      pwd.focus();
    });
    form.addEventListener('submit',function(){
      btn.classList.add('loading');
      btn.querySelector('.btn-text').textContent='Authenticating...';
    });
  })();
  </script></html>`;
}
__name(loginHtml, "loginHtml");
function forgotPasswordHtml(csrf, error = "") {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Forgot Password \u2014 DomisLink SSO</title><style>
  *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#071d17;color:#f5f5f0;font:16px system-ui}.card{width:min(420px,calc(100% - 32px));padding:32px;border:1px solid #355448;border-radius:22px;background:#0d2a22;box-shadow:0 24px 80px #0005}h1{margin:0 0 8px;font-size:27px}.muted{color:#b6c8bd;font-size:14px}label{display:block;margin:18px 0 7px;font-size:14px}input{width:100%;padding:13px;border-radius:10px;border:1px solid #557267;background:#071d17;color:white;font:inherit}button{margin-top:22px;width:100%;padding:14px;border:0;border-radius:10px;background:#d6b65c;color:#172019;font-weight:700;font-size:15px;cursor:pointer}.error{color:#ffb4a9;background:#48231e;padding:10px;border-radius:8px;margin:16px 0}.brand{color:#e3c66c;font-weight:800;letter-spacing:.08em;font-size:12px;margin-bottom:22px}.back-link{display:block;text-align:center;margin-top:18px;color:#b6c8bd;font-size:13px;text-decoration:none}.back-link:hover{color:#e3c66c}
  </style><main class="card"><div class="brand">DOMISLINK \u00B7 THE DIGITAL EMPIRE</div><h1>Forgot Password</h1><p class="muted">Enter your email and we will send you a verification code.</p>${error ? `<div class="error">${htmlEscape(error)}</div>` : ""}<form method="post" action="/forgot-password"><input type="hidden" name="csrf" value="${csrf}"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" required><button type="submit">Send Verification Code</button></form><a class="back-link" href="/login">\u2190 Back to sign in</a></main></html>`;
}
__name(forgotPasswordHtml, "forgotPasswordHtml");
function resetPasswordHtml(email, csrf, error = "") {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Reset Password \u2014 DomisLink SSO</title><style>
  *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#071d17;color:#f5f5f0;font:16px system-ui}.card{width:min(420px,calc(100% - 32px));padding:32px;border:1px solid #355448;border-radius:22px;background:#0d2a22;box-shadow:0 24px 80px #0005}h1{margin:0 0 8px;font-size:27px}.muted{color:#b6c8bd;font-size:14px}label{display:block;margin:18px 0 7px;font-size:14px}input{width:100%;padding:13px;border-radius:10px;border:1px solid #557267;background:#071d17;color:white;font:inherit}button{margin-top:22px;width:100%;padding:14px;border:0;border-radius:10px;background:#d6b65c;color:#172019;font-weight:700;font-size:15px;cursor:pointer}.error{color:#ffb4a9;background:#48231e;padding:10px;border-radius:8px;margin:16px 0}.brand{color:#e3c66c;font-weight:800;letter-spacing:.08em;font-size:12px;margin-bottom:22px}.back-link{display:block;text-align:center;margin-top:18px;color:#b6c8bd;font-size:13px;text-decoration:none}.back-link:hover{color:#e3c66c}.pwd-wrap{position:relative}input.pwd-input{padding-right:44px}.pwd-toggle{position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:15px;color:#b6c8bd;padding:6px 8px;border-radius:6px}.pwd-toggle:hover{color:#e3c66c}
  </style><main class="card"><div class="brand">DOMISLINK \u00B7 THE DIGITAL EMPIRE</div><h1>Reset Password</h1><p class="muted">Enter the code sent to ${htmlEscape(email)} and your new password.</p>${error ? `<div class="error">${htmlEscape(error)}</div>` : ""}<form method="post" action="/reset-password"><input type="hidden" name="email" value="${htmlEscape(email)}"><input type="hidden" name="csrf" value="${csrf}"><label for="code">Verification code</label><input id="code" name="code" inputmode="numeric" maxlength="6" placeholder="000000" required><label for="newPassword">New password (min 12 characters)</label><div class="pwd-wrap"><input id="newPassword" name="newPassword" type="password" class="pwd-input" autocomplete="new-password" minlength="12" required><button type="button" class="pwd-toggle" id="pwdToggle">&#128065;</button></div><label for="confirmPassword">Confirm new password</label><input id="confirmPassword" name="confirmPassword" type="password" autocomplete="new-password" minlength="12" required><button type="submit">Reset Password</button></form><a class="back-link" href="/login">\u2190 Back to sign in</a></main><script>
  (function(){var p=document.getElementById('newPassword'),t=document.getElementById('pwdToggle'),s=false;t.addEventListener('click',function(){s=!s;p.type=s?'text':'password';t.innerHTML=s?'&#128064;':'&#128065;';p.focus();});})();
  </script></html>`;
}
__name(resetPasswordHtml, "resetPasswordHtml");
function safeInternalReturn(value) {
  if (!value || !value.startsWith("/oauth/authorize?")) return "/account";
  try {
    const u = new URL(value, ISSUER_DEFAULT);
    return u.origin === ISSUER_DEFAULT ? value : "/account";
  } catch {
    return "/account";
  }
}
__name(safeInternalReturn, "safeInternalReturn");
async function sessionUser(request, env) {
  const token = readCookie(request.headers.get("Cookie") || void 0, "dl_sso_session");
  if (!token) return null;
  const row = await env.DB.prepare("SELECT u.id,u.email,u.full_name FROM sso_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.status='active' LIMIT 1").bind(await sha256(token), (/* @__PURE__ */ new Date()).toISOString()).first();
  return row ? { id: row.id, email: row.email, fullName: row.full_name } : null;
}
__name(sessionUser, "sessionUser");
async function issueSession3(env, userId) {
  const token = randomToken(32), now = /* @__PURE__ */ new Date(), expires = new Date(now.getTime() + SSO_SESSION_SECONDS * 1e3).toISOString();
  await env.DB.prepare("INSERT INTO sso_sessions(id,token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?,?)").bind(crypto.randomUUID(), await sha256(token), userId, now.toISOString(), expires).run();
  return token;
}
__name(issueSession3, "issueSession");
function pemBytes(pem) {
  const base64 = pem.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "").replace(/\s/g, "");
  const binary = atob(base64);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return bytes.slice().buffer;
}
__name(pemBytes, "pemBytes");
async function signingKey(env) {
  if (!env.OIDC_PRIVATE_KEY_PEM) throw new Error("OIDC_PRIVATE_KEY_PEM is not configured");
  return crypto.subtle.importKey("pkcs8", pemBytes(env.OIDC_PRIVATE_KEY_PEM), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
}
__name(signingKey, "signingKey");
async function idToken(env, claims) {
  const header = { alg: "RS256", typ: "JWT", kid: env.OIDC_KEY_ID || "domislink-sso-2026" };
  const body = { iss: issuer(env), iat: Math.floor(Date.now() / 1e3), ...claims };
  const signingInput = `${b64url2(enc2.encode(JSON.stringify(header)))}.${b64url2(enc2.encode(JSON.stringify(body)))}`;
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", await signingKey(env), enc2.encode(signingInput));
  return `${signingInput}.${b64url2(new Uint8Array(signature))}`;
}
__name(idToken, "idToken");
async function adstudioAccessToken(env, userId) {
  const roles = await env.DB.prepare("SELECT role FROM adstudio_role_assignments WHERE user_id=? AND revoked_at IS NULL AND role IN ('admin','moderator','advertiser') ORDER BY role").bind(userId).all();
  const allowed = (roles.results || []).map(row => row.role);
  // Do not grant roles based on registration, email, tenant membership, or client input.
  if (!allowed.length) return null;
  const now = Math.floor(Date.now() / 1000);
  return idToken(env, { sub: userId, aud: "domislink-adstudio", exp: now + 900, nbf: now, jti: crypto.randomUUID(), adstudio_roles: allowed });
}
__name(adstudioAccessToken, "adstudioAccessToken");
async function jwks(env) {
  if (!env.OIDC_PUBLIC_KEY_PEM) throw new Error("OIDC_PUBLIC_KEY_PEM is not configured");
  const key = await crypto.subtle.importKey("spki", pemBytes(env.OIDC_PUBLIC_KEY_PEM), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, true, ["verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", key);
  return { keys: [{ kty: "RSA", use: "sig", alg: "RS256", kid: env.OIDC_KEY_ID || "domislink-sso-2026", n: jwk.n, e: jwk.e }] };
}
__name(jwks, "jwks");
async function activeClient(env, clientId) {
  return env.DB.prepare("SELECT client_id,client_name,redirect_uris,allowed_scopes,enabled FROM sso_clients WHERE client_id=? AND enabled=1").bind(clientId).first();
}
__name(activeClient, "activeClient");
async function authorizedTenant(env, userId, tenantId) {
  return env.DB.prepare("SELECT m.role FROM platform_tenant_memberships m JOIN platform_tenants t ON t.id=m.tenant_id WHERE m.user_id=? AND m.tenant_id=? AND m.status='active' AND t.status='active' LIMIT 1").bind(userId, tenantId).first();
}
__name(authorizedTenant, "authorizedTenant");
function allowedOrigin(request, env) {
  const origin = request.headers.get("Origin");
  if (!origin) return null;
  const allowed = (env.SSO_ALLOWED_ORIGINS || "https://church.domislink.com").split(",").map((v) => v.trim()).filter(Boolean);
  if (allowed.includes(origin)) return origin;
  try {
    const parsed = new URL(origin);
    if (parsed.protocol === "https:" && (parsed.hostname === "domislink.com" || parsed.hostname.endsWith(".domislink.com"))) return origin;
  } catch {
  }
  return null;
}
__name(allowedOrigin, "allowedOrigin");
function corsHeaders(request, env) {
  const origin = allowedOrigin(request, env);
  return origin ? { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true", "Access-Control-Allow-Headers": "Content-Type,Authorization", "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS", "Vary": "Origin" } : {};
}
__name(corsHeaders, "corsHeaders");
async function hmacKey(raw, usages) {
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, usages);
}
__name(hmacKey, "hmacKey");
async function encryptToken(env, token) {
  if (!env.WHATSAPP_TOKEN_ENCRYPTION_KEY) throw new Error("WHATSAPP_TOKEN_ENCRYPTION_KEY is not configured");
  const keyBytes = fromB64(env.WHATSAPP_TOKEN_ENCRYPTION_KEY);
  if (keyBytes.length !== 32) throw new Error("WhatsApp encryption key must be 32 bytes encoded as base64");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc2.encode(token));
  return { ciphertext: b64url2(new Uint8Array(encrypted)), iv: b64url2(iv) };
}
__name(encryptToken, "encryptToken");
async function decryptToken(env, ciphertext, ivText) {
  if (!env.WHATSAPP_TOKEN_ENCRYPTION_KEY) throw new Error("WHATSAPP_TOKEN_ENCRYPTION_KEY is not configured");
  const keyBytes = fromB64(env.WHATSAPP_TOKEN_ENCRYPTION_KEY);
  if (keyBytes.length !== 32) throw new Error("WhatsApp encryption key must be 32 bytes encoded as base64");
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(ivText) }, key, fromB64(ciphertext));
  return new TextDecoder().decode(clear);
}
__name(decryptToken, "decryptToken");
async function metaCodeExchange(env, code) {
  if (!env.META_APP_ID || !env.META_APP_SECRET) throw new Error("Meta app credentials are not configured");
  const url = new URL(`https://graph.facebook.com/${graphVersion(env)}/oauth/access_token`);
  url.searchParams.set("client_id", env.META_APP_ID);
  url.searchParams.set("client_secret", env.META_APP_SECRET);
  url.searchParams.set("code", code);
  const response = await fetch(url);
  const data = await response.json();
  if (!response.ok || !data.access_token) throw new Error(data.error?.message || "Meta authorization code exchange failed");
  return data;
}
__name(metaCodeExchange, "metaCodeExchange");
async function verifyMetaSignature(raw, signature, secret) {
  if (!signature?.startsWith("sha256=")) return false;
  const expected = signature.slice(7);
  const key = await hmacKey(enc2.encode(secret), ["sign"]);
  const digest = await crypto.subtle.sign("HMAC", key, enc2.encode(raw));
  const actual = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  if (actual.length !== expected.length) return false;
  let mismatch = 0;
  for (let i = 0; i < actual.length; i++) mismatch |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  return mismatch === 0;
}
__name(verifyMetaSignature, "verifyMetaSignature");
async function handleWhatsAppWebhook(request, env) {
  const url = new URL(request.url);
  if (request.method === "GET") {
    const mode = url.searchParams.get("hub.mode"), token = url.searchParams.get("hub.verify_token"), challenge = url.searchParams.get("hub.challenge");
    return mode === "subscribe" && token && token === env.META_WEBHOOK_VERIFY_TOKEN && challenge ? new Response(challenge, { status: 200 }) : new Response("Forbidden", { status: 403 });
  }
  const raw = await request.text();
  if (!env.META_APP_SECRET || !await verifyMetaSignature(raw, request.headers.get("X-Hub-Signature-256"), env.META_APP_SECRET)) return new Response("Invalid signature", { status: 401 });
  const payload = JSON.parse(raw);
  for (const entry of payload.entry || []) for (const change of entry.changes || []) {
    const phoneId = change.value?.metadata?.phone_number_id || null;
    const connection = phoneId ? await env.DB.prepare("SELECT tenant_id FROM whatsapp_connections WHERE phone_number_id=? AND status='active' LIMIT 1").bind(phoneId).first() : null;
    const receivedAt = (/* @__PURE__ */ new Date()).toISOString();
    await env.DB.prepare("INSERT INTO whatsapp_webhook_events(id,tenant_id,phone_number_id,event_type,payload_json,received_at) VALUES(?,?,?,?,?,?)").bind(crypto.randomUUID(), connection?.tenant_id || null, phoneId, change.field || "unknown", JSON.stringify(change.value || {}), receivedAt).run();
    if (connection?.tenant_id && Array.isArray(change.value?.statuses)) {
      for (const statusItem of change.value.statuses) {
        const deliveryStatus = statusItem.status === "failed" ? "failed" : statusItem.status === "delivered" || statusItem.status === "read" ? "delivered" : null;
        if (!deliveryStatus || !statusItem.id) continue;
        const providerTime = statusItem.timestamp && /^\d+$/.test(statusItem.timestamp) ? new Date(Number(statusItem.timestamp) * 1e3).toISOString() : receivedAt;
        const errorText = statusItem.errors?.map((item) => item.title || item.message || String(item.code || "")).filter(Boolean).join("; ").slice(0, 300) || null;
        await env.DB.prepare("UPDATE church_message_deliveries SET status=?,delivered_at=CASE WHEN ?='delivered' THEN ? ELSE delivered_at END,error_message=CASE WHEN ?='failed' THEN ? ELSE error_message END,updated_at=? WHERE church_id=? AND channel='whatsapp' AND provider_message_id=? AND status IN ('accepted','sending','queued')").bind(deliveryStatus, deliveryStatus, providerTime, deliveryStatus, errorText, receivedAt, connection.tenant_id, statusItem.id).run();
      }
    }
  }
  return json3({ ok: true });
}
__name(handleWhatsAppWebhook, "handleWhatsAppWebhook");
async function fetchCurrentUser(request, env) {
  const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const row = await env.DB.prepare("SELECT u.id,u.email,u.full_name,u.email_verified_at,u.phone,t.client_id,t.scope FROM sso_access_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=? AND t.revoked_at IS NULL AND t.expires_at>? AND u.status='active' LIMIT 1").bind(await sha256(token), (/* @__PURE__ */ new Date()).toISOString()).first();
  if (!row) return null;
  const verifiedPhone = row.phone ? await env.DB.prepare("SELECT phone_e164 FROM sso_verified_phones WHERE user_id=? AND phone_e164=? LIMIT 1").bind(row.id, row.phone).first() : null;
  return { id: row.id, email: row.email_verified_at ? row.email : void 0, phone: verifiedPhone?.phone_e164, fullName: row.full_name, clientId: row.client_id, scope: row.scope };
}
__name(fetchCurrentUser, "fetchCurrentUser");
async function handle(request, env) {
  const url = new URL(request.url), path = url.pathname;
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request, env) });
  const recovery=await handleRecovery(request,env,path,{forgot:forgotPasswordHtml,reset:resetPasswordHtml,send:sendEmailOtp,limit:consumeRateLimit});
  if(recovery)return recovery;
  const identityChannelResponse = await handleIdentityChannel(request, env, path);
  if (identityChannelResponse) return identityChannelResponse;
  const passkeyResponse = await handlePasskey(request, env, path);
  if (passkeyResponse) return passkeyResponse;
  if (path === "/auth/session" && request.method === "GET") {
    const user = await sessionUser(request, env);
    if (!user) return json3({ authenticated: false }, 401);
    const passkeys = await env.DB.prepare("SELECT COUNT(*) AS total FROM sso_passkeys WHERE user_id=?").bind(user.id).first();
    return json3({ authenticated: true, user: { id: user.id, fullName: user.fullName }, passkeyCount: passkeys?.total || 0 });
  }
  if (path === "/" || path === "/install" || path === "/account") return new Response(identityPwaHtml, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache", "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; worker-src 'self'; img-src 'self' data:; manifest-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Permissions-Policy": "publickey-credentials-get=(self), publickey-credentials-create=(self)" } });
  if (path === "/manifest.webmanifest") return new Response(JSON.stringify(identityManifest), { headers: { "Content-Type": "application/manifest+json", "Cache-Control": "public, max-age=3600" } });
  if (path === "/icon.svg") return new Response(identityIcon, { headers: { "Content-Type": "image/svg+xml", "Cache-Control": "public, max-age=86400" } });
  if (path === "/sw.js") return new Response(identityServiceWorker, { headers: { "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "no-cache", "Service-Worker-Allowed": "/" } });
  if (path === "/health") return json3({ ok: true, service: "domislink-universal-sso", issuer: issuer(env) });
  if (path === "/.well-known/openid-configuration") return json3({
    issuer: issuer(env),
    authorization_endpoint: issuer(env) + "/oauth/authorize",
    token_endpoint: issuer(env) + "/oauth/token",
    userinfo_endpoint: issuer(env) + "/oauth/userinfo",
    jwks_uri: issuer(env) + "/oauth/jwks",
    revocation_endpoint: issuer(env) + "/oauth/revoke",
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid", "profile", "email", "phone"],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"]
  });
  if (path === "/oauth/jwks") {
    try {
      return json3(await jwks(env));
    } catch (e) {
      return json3({ error: e instanceof Error ? e.message : "JWKS unavailable" }, 503);
    }
  }
  if (path === "/login" && request.method === "GET") { const csrf=randomToken(24); return new Response(loginHtml(safeInternalReturn(url.searchParams.get("return_to")||""),csrf), {headers:{"Content-Type":"text/html; charset=utf-8","Set-Cookie":cookie("dl_sso_csrf",csrf,600),"Cache-Control":"no-store","Referrer-Policy":"no-referrer","Content-Security-Policy":"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'","X-Content-Type-Options":"nosniff"}}); }
  if (path === "/identity" && request.method === "GET") return new Response(identityPwaHtml, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache", "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; worker-src 'self'; img-src 'self' data:; manifest-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Permissions-Policy": "publickey-credentials-get=(self), publickey-credentials-create=(self)" } });
  if (path === "/login" && request.method === "POST") {
    const form = await request.formData();
    const csrf = String(form.get("csrf") || ""), csrfCookie = readCookie(request.headers.get("Cookie") || void 0, "dl_sso_csrf");
    const returnTo = safeInternalReturn(String(form.get("return_to") || ""));
    const email = String(form.get("email") || "").trim().toLowerCase(), password = String(form.get("password") || "");
    if (!csrf || !csrfCookie || csrf !== csrfCookie) {
      const nextCsrf = randomToken(24);
      return new Response(loginHtml(returnTo, nextCsrf, "Your sign-in request expired. Please try again."), { status: 403, headers: { "Content-Type": "text/html; charset=utf-8", "Set-Cookie": cookie("dl_sso_csrf", nextCsrf, 600) } });
    }
    const user = await env.DB.prepare("SELECT id,email,full_name,password_hash,status FROM users WHERE email=? LIMIT 1").bind(email).first();
    if (!user || user.status !== "active" || !user.password_hash || !await verifyPassword(password, user.password_hash)) {
      const nextCsrf = randomToken(24);
      return new Response(loginHtml(returnTo, nextCsrf, "Email or password is incorrect."), { status: 401, headers: { "Content-Type": "text/html; charset=utf-8", "Set-Cookie": cookie("dl_sso_csrf", nextCsrf, 600) } });
    }
    const session = await issueSession3(env, user.id);
    const headers = new Headers({ Location: returnTo, "Cache-Control": "no-store" });
    headers.append("Set-Cookie", cookie("dl_sso_session", session, SSO_SESSION_SECONDS));
    headers.append("Set-Cookie", clearCookie("dl_sso_csrf"));
    return new Response(null, { status: 302, headers });
  }
  if (path === "/logout" && request.method === "POST") {
    const trustedOrigin2 = allowedOrigin(request, env);
    const fetchSite = request.headers.get("Sec-Fetch-Site");
    if (!trustedOrigin2 || fetchSite && !["same-origin", "same-site"].includes(fetchSite)) {
      return json3({ error: "same_origin_required" }, 403);
    }
    const token = readCookie(request.headers.get("Cookie") || void 0, "dl_sso_session");
    if (token) await env.DB.prepare("DELETE FROM sso_sessions WHERE token_hash=?").bind(await sha256(token)).run();
    return new Response(null, { status: 302, headers: { Location: "/login", "Set-Cookie": clearCookie("dl_sso_session"), "Cache-Control": "no-store" } });
  }
  if (path === "/oauth/authorize" && request.method === "GET") {
    const clientId = url.searchParams.get("client_id") || "", redirectUri = url.searchParams.get("redirect_uri") || "";
    const responseType = url.searchParams.get("response_type"), challenge = url.searchParams.get("code_challenge") || "";
    const challengeMethod = url.searchParams.get("code_challenge_method"), state = url.searchParams.get("state") || "", nonce = url.searchParams.get("nonce");
    const scope = (url.searchParams.get("scope") || "openid profile email phone").split(/\s+/).filter(Boolean);
    const client = await activeClient(env, clientId);
    if (!client || responseType !== "code") {
      return json3({ error: "invalid_request", error_description: "Invalid client or response type." }, 400);
    }
    let registeredRedirects;
    try {
      registeredRedirects = JSON.parse(client.redirect_uris);
    } catch {
      return json3({ error: "invalid_request", error_description: "Invalid client redirect configuration." }, 400);
    }
    if (!Array.isArray(registeredRedirects) || !registeredRedirects.every((value) => typeof value === "string") || !registeredRedirects.includes(redirectUri) || challengeMethod !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(challenge) || !nonce || nonce.length > 256 || !state || state.length > 512 || !scope.includes("openid") || new Set(scope).size !== scope.length || scope.some((s) => !client.allowed_scopes.split(/\s+/).includes(s))) {
      return json3({ error: "invalid_request", error_description: "Invalid client, redirect URI, PKCE, state or scope." }, 400);
    }
    const user = await sessionUser(request, env);
    if (!user) return new Response(null, { status: 302, headers: { Location: "/login?return_to=" + encodeURIComponent(path + url.search) } });
    const code = randomToken(32), expires = new Date(Date.now() + 12e4).toISOString();
    await env.DB.prepare("INSERT INTO sso_authorization_codes(code_hash,client_id,user_id,redirect_uri,code_challenge,nonce,scope,expires_at) VALUES(?,?,?,?,?,?,?,?)").bind(await sha256(code), clientId, user.id, redirectUri, challenge, nonce, scope.join(" "), expires).run();
    const target = new URL(redirectUri);
    target.searchParams.set("code", code);
    target.searchParams.set("state", state);
    return new Response(null, { status: 302, headers: { Location: target.toString(), "Cache-Control": "no-store" } });
  }
  if (path === "/oauth/token" && request.method === "POST") {
    const form = await request.formData(), grant = String(form.get("grant_type") || ""), clientId = String(form.get("client_id") || "");
    if (!await authenticateTokenClient(env.DB, form)) return json3({ error: "invalid_client" }, 401);
    if (grant === "authorization_code") {
      const code = String(form.get("code") || ""), redirectUri = String(form.get("redirect_uri") || ""), verifier = String(form.get("code_verifier") || "");
      if (!code || !verifier || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return json3({ error: "invalid_grant" }, 400);
      const codeHash = await sha256(code);
      const candidate = await env.DB.prepare("SELECT user_id,nonce,scope,code_challenge FROM sso_authorization_codes WHERE code_hash=? AND client_id=? AND redirect_uri=? AND used_at IS NULL AND expires_at>?").bind(codeHash, clientId, redirectUri, (/* @__PURE__ */ new Date()).toISOString()).first();
      if (!candidate) return json3({ error: "invalid_grant" }, 400);
      const verifierHash = b64url2(new Uint8Array(await crypto.subtle.digest("SHA-256", enc2.encode(verifier))));
      if (verifierHash !== candidate.code_challenge) return json3({ error: "invalid_grant" }, 400);
      const row = await env.DB.prepare("UPDATE sso_authorization_codes SET used_at=? WHERE code_hash=? AND client_id=? AND redirect_uri=? AND used_at IS NULL AND expires_at>? RETURNING user_id,nonce,scope").bind((/* @__PURE__ */ new Date()).toISOString(), codeHash, clientId, redirectUri, (/* @__PURE__ */ new Date()).toISOString()).first();
      if (!row) return json3({ error: "invalid_grant" }, 400);
      const user = await env.DB.prepare("SELECT id,email,full_name,email_verified_at,phone FROM users WHERE id=? AND status='active'").bind(row.user_id).first();
      if (!user) return json3({ error: "invalid_grant" }, 400);
      const access = randomToken(32), refresh = randomToken(48), now = /* @__PURE__ */ new Date(), accessExpiry = new Date(now.getTime() + ACCESS_SECONDS * 1e3), refreshExpiry = new Date(now.getTime() + REFRESH_SECONDS * 1e3);
      await env.DB.batch([
        env.DB.prepare("INSERT INTO sso_access_tokens(token_hash,client_id,user_id,scope,expires_at) VALUES(?,?,?,?,?)").bind(await sha256(access), clientId, user.id, row.scope, accessExpiry.toISOString()),
        env.DB.prepare("INSERT INTO sso_refresh_tokens(token_hash,client_id,user_id,scope,expires_at) VALUES(?,?,?,?,?)").bind(await sha256(refresh), clientId, user.id, row.scope, refreshExpiry.toISOString())
      ]);
      const phoneVerified = user.phone ? await env.DB.prepare("SELECT phone_e164 FROM sso_verified_phones WHERE user_id=? AND phone_e164=? LIMIT 1").bind(user.id, user.phone).first() : null;
      const token = await idToken(env, { sub: user.id, aud: clientId, exp: Math.floor(accessExpiry.getTime() / 1e3), nonce: row.nonce || void 0, email: row.scope.includes("email") && user.email_verified_at ? user.email : void 0, email_verified: row.scope.includes("email") ? Boolean(user.email_verified_at) : void 0, phone_number: row.scope.includes("phone") && phoneVerified ? user.phone : void 0, phone_number_verified: row.scope.includes("phone") ? Boolean(phoneVerified) : void 0, name: row.scope.includes("profile") ? user.full_name : void 0 });
      const apiToken = clientId === "domislink-adstudio" ? await adstudioAccessToken(env, user.id) : access;
      return json3({ access_token: apiToken || access, token_type: "Bearer", expires_in: apiToken ? 900 : ACCESS_SECONDS, refresh_token: refresh, id_token: token, scope: row.scope });
    }
    if (grant === "refresh_token") {
      const refresh = String(form.get("refresh_token") || "");
      const row = await env.DB.prepare("UPDATE sso_refresh_tokens SET revoked_at=? WHERE token_hash=? AND client_id=? AND revoked_at IS NULL AND expires_at>? RETURNING user_id,scope").bind((/* @__PURE__ */ new Date()).toISOString(), await sha256(refresh), clientId, (/* @__PURE__ */ new Date()).toISOString()).first();
      if (!row) return json3({ error: "invalid_grant" }, 400);
      const user = await env.DB.prepare("SELECT id,email,full_name,email_verified_at,phone FROM users WHERE id=? AND status='active'").bind(row.user_id).first();
      if (!user) return json3({ error: "invalid_grant" }, 400);
      const access = randomToken(32), nextRefresh = randomToken(48), now = /* @__PURE__ */ new Date(), accessExpiry = new Date(now.getTime() + ACCESS_SECONDS * 1e3);
      await env.DB.batch([
        env.DB.prepare("INSERT INTO sso_access_tokens(token_hash,client_id,user_id,scope,expires_at) VALUES(?,?,?,?,?)").bind(await sha256(access), clientId, user.id, row.scope, accessExpiry.toISOString()),
        env.DB.prepare("INSERT INTO sso_refresh_tokens(token_hash,client_id,user_id,scope,expires_at) VALUES(?,?,?,?,?)").bind(await sha256(nextRefresh), clientId, user.id, row.scope, new Date(now.getTime() + REFRESH_SECONDS * 1e3).toISOString())
      ]);
      const phoneVerified = user.phone ? await env.DB.prepare("SELECT phone_e164 FROM sso_verified_phones WHERE user_id=? AND phone_e164=? LIMIT 1").bind(user.id, user.phone).first() : null;
      const token = await idToken(env, { sub: user.id, aud: clientId, exp: Math.floor(accessExpiry.getTime() / 1e3), email: row.scope.includes("email") && user.email_verified_at ? user.email : void 0, email_verified: row.scope.includes("email") ? Boolean(user.email_verified_at) : void 0, phone_number: row.scope.includes("phone") && phoneVerified ? user.phone : void 0, phone_number_verified: row.scope.includes("phone") ? Boolean(phoneVerified) : void 0, name: row.scope.includes("profile") ? user.full_name : void 0 });
      const apiToken = clientId === "domislink-adstudio" ? await adstudioAccessToken(env, user.id) : access;
      return json3({ access_token: apiToken || access, token_type: "Bearer", expires_in: apiToken ? 900 : ACCESS_SECONDS, refresh_token: nextRefresh, id_token: token, scope: row.scope });
    }
    return json3({ error: "unsupported_grant_type" }, 400);
  }
  if (path === "/oauth/userinfo" && request.method === "GET") {
    const user = await fetchCurrentUser(request, env);
    return user ? json3({ sub: user.id, aud: user.clientId, ...user.scope.split(" ").includes("email") && user.email ? { email: user.email, email_verified: true } : {}, ...user.scope.split(" ").includes("phone") && user.phone ? { phone_number: user.phone, phone_number_verified: true } : {}, ...user.scope.split(" ").includes("profile") ? { name: user.fullName } : {} }) : json3({ error: "invalid_token" }, 401);
  }
  if (path === "/oauth/revoke" && request.method === "POST") {
    const form = await request.formData(), token = String(form.get("token") || ""), clientId = String(form.get("client_id") || ""), hash = await sha256(token), now = (/* @__PURE__ */ new Date()).toISOString();
    if (!token || !clientId) return json3({ error: "invalid_request" }, 400);
    await env.DB.batch([
      env.DB.prepare("UPDATE sso_access_tokens SET revoked_at=? WHERE token_hash=? AND client_id=? AND revoked_at IS NULL").bind(now, hash, clientId),
      env.DB.prepare("UPDATE sso_refresh_tokens SET revoked_at=? WHERE token_hash=? AND client_id=? AND revoked_at IS NULL").bind(now, hash, clientId)
    ]);
    return json3({ ok: true });
  }
  if (path === "/admin/tenants" && request.method === "POST") {
    const supplied = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");
    if (!env.SSO_ADMIN_API_KEY || supplied !== env.SSO_ADMIN_API_KEY) return json3({ error: "unauthorized" }, 401);
    const body = await request.json();
    const productKey = (body.product_key || "").trim().toLowerCase(), resourceId = (body.resource_id || "").trim(), displayName = (body.display_name || "").trim();
    if (!/^[a-z][a-z0-9_-]{1,39}$/.test(productKey) || !resourceId || resourceId.length > 160 || !displayName || displayName.length > 160 || !body.owner_user_id) return json3({ error: "product_key, resource_id, display_name and owner_user_id are required" }, 400);
    const owner = await env.DB.prepare("SELECT id FROM users WHERE id=? AND status='active' LIMIT 1").bind(body.owner_user_id).first();
    if (!owner) return json3({ error: "owner_user_not_found" }, 404);
    const proposedId = body.tenant_id || crypto.randomUUID(), now = (/* @__PURE__ */ new Date()).toISOString();
    await env.DB.prepare("INSERT OR IGNORE INTO platform_tenants(id,product_key,resource_id,display_name,status,created_at,updated_at) VALUES(?,?,?,?, 'active',?,?)").bind(proposedId, productKey, resourceId, displayName, now, now).run();
    const tenant = await env.DB.prepare("SELECT id FROM platform_tenants WHERE product_key=? AND resource_id=? AND status='active' LIMIT 1").bind(productKey, resourceId).first();
    if (!tenant) return json3({ error: "tenant_registration_failed" }, 500);
    await env.DB.prepare("INSERT INTO platform_tenant_memberships(id,tenant_id,user_id,role,status,created_at,updated_at) VALUES(?,?,?,'owner','active',?,?) ON CONFLICT(tenant_id,user_id) DO UPDATE SET role='owner',status='active',updated_at=excluded.updated_at").bind(crypto.randomUUID(), tenant.id, owner.id, now, now).run();
    return json3({ tenant_id: tenant.id, product_key: productKey, resource_id: resourceId, display_name: displayName }, 201);
  }
  if (path.startsWith("/admin/clients") && request.method === "POST") {
    const supplied = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");
    if (!env.SSO_ADMIN_API_KEY || supplied !== env.SSO_ADMIN_API_KEY) return json3({ error: "unauthorized" }, 401);
    const body = await request.json();
    const name = body.client_name?.trim(), redirects = body.redirect_uris;
    if (!name || !Array.isArray(redirects) || redirects.length < 1 || redirects.length > 20 || redirects.some((uri) => {
      try {
        const u = new URL(uri);
        return u.protocol !== "https:" && u.hostname !== "localhost";
      } catch {
        return true;
      }
    })) return json3({ error: "invalid_client_registration" }, 400);
    const clientId = "dl_" + randomToken(24), scopes = (body.allowed_scopes || ["openid", "profile", "email", "phone"]).filter((s) => ["openid", "profile", "email", "phone"].includes(s));
    await env.DB.prepare("INSERT INTO sso_clients(client_id,client_name,redirect_uris,allowed_scopes,enabled,created_at) VALUES(?,?,?,?,1,?)").bind(clientId, name, JSON.stringify(redirects), scopes.join(" "), (/* @__PURE__ */ new Date()).toISOString()).run();
    return json3({ client_id: clientId, client_name: name, redirect_uris: redirects, allowed_scopes: scopes }, 201);
  }
  if (path === "/api/whatsapp/config" && request.method === "GET") {
    return json3({ app_id: env.META_APP_ID || null, config_id: env.META_WHATSAPP_CONFIG_ID || null, graph_version: graphVersion(env), configured: Boolean(env.META_APP_ID && env.META_WHATSAPP_CONFIG_ID) }, 200, corsHeaders(request, env));
  }
  if (path === "/api/whatsapp/connections" && request.method === "POST") {
    const headers = corsHeaders(request, env);
    const user = await sessionUser(request, env);
    if (!user) return json3({ error: "authentication_required" }, 401, headers);
    const body = await request.json();
    const tenantId = body.tenant_id || "", code = body.code || "", wabaId = body.waba_id || "", phoneId = body.phone_number_id || "";
    if (!tenantId || !code || !wabaId || !phoneId) return json3({ error: "tenant_id, code, waba_id and phone_number_id are required" }, 400, headers);
    const membership = await authorizedTenant(env, user.id, tenantId);
    if (!membership || !["owner", "church_admin"].includes(membership.role)) return json3({ error: "tenant_admin_required" }, 403, headers);
    const tokenData = await metaCodeExchange(env, code);
    if (typeof tokenData.access_token !== "string" || !tokenData.access_token.trim()) return json3({ error: "Meta did not return an access token." }, 502, headers);
    const version = graphVersion(env);
    const [phoneResponse, wabaResponse] = await Promise.all([
      fetch(`https://graph.facebook.com/${version}/${encodeURIComponent(phoneId)}?fields=id,display_phone_number,verified_name`, { headers: { Authorization: `Bearer ${tokenData.access_token}` } }),
      fetch(`https://graph.facebook.com/${version}/${encodeURIComponent(wabaId)}/phone_numbers?fields=id,display_phone_number,verified_name&limit=100`, { headers: { Authorization: `Bearer ${tokenData.access_token}` } })
    ]);
    const phone = await phoneResponse.json();
    const waba = await wabaResponse.json();
    if (!phoneResponse.ok || !wabaResponse.ok || phone.id !== phoneId || !waba.data?.some((item) => item.id === phoneId)) return json3({ error: phone.error?.message || waba.error?.message || "The phone number could not be verified as part of this WhatsApp Business Account." }, 400, headers);
    const subscribe = await fetch(`https://graph.facebook.com/${version}/${encodeURIComponent(wabaId)}/subscribed_apps`, { method: "POST", headers: { Authorization: `Bearer ${tokenData.access_token}` } });
    const subscribeData = await subscribe.json();
    if (!subscribe.ok) return json3({ error: subscribeData.error?.message || "Meta webhook subscription failed. Reconnect after reviewing the granted permissions." }, 400, headers);
    const existing = await env.DB.prepare("SELECT tenant_id FROM whatsapp_connections WHERE phone_number_id=? LIMIT 1").bind(phoneId).first();
    if (existing && existing.tenant_id !== tenantId) return json3({ error: "This WhatsApp phone number is already connected to another DomisLink organisation. Disconnect it there first." }, 409, headers);
    const encrypted = await encryptToken(env, tokenData.access_token), now = (/* @__PURE__ */ new Date()).toISOString();
    await env.DB.prepare(`INSERT INTO whatsapp_connections(id,tenant_id,waba_id,phone_number_id,business_id,display_phone_number,verified_name,access_token_ciphertext,token_iv,token_expires_at,status,connected_by,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,'active',?,?,?)
      ON CONFLICT(phone_number_id) DO UPDATE SET waba_id=excluded.waba_id,business_id=excluded.business_id,display_phone_number=excluded.display_phone_number,verified_name=excluded.verified_name,access_token_ciphertext=excluded.access_token_ciphertext,token_iv=excluded.token_iv,token_expires_at=excluded.token_expires_at,status='active',connected_by=excluded.connected_by,updated_at=excluded.updated_at
      WHERE whatsapp_connections.tenant_id=excluded.tenant_id`).bind(crypto.randomUUID(), tenantId, wabaId, phoneId, body.business_id || null, phone.display_phone_number || null, phone.verified_name || null, encrypted.ciphertext, encrypted.iv, tokenData.expires_in ? new Date(Date.now() + tokenData.expires_in * 1e3).toISOString() : null, user.id, now, now).run();
    return json3({ ok: true, connection: { tenant_id: tenantId, waba_id: wabaId, phone_number_id: phoneId, display_phone_number: phone.display_phone_number || null, verified_name: phone.verified_name || null, webhook_subscribed: true } }, 201, headers);
  }
  if (path === "/api/whatsapp/connections" && request.method === "GET") {
    const user = await sessionUser(request, env), tenantId = url.searchParams.get("tenant_id") || "";
    const headers = corsHeaders(request, env);
    if (!user) return json3({ error: "authentication_required" }, 401, headers);
    const membership = await authorizedTenant(env, user.id, tenantId);
    if (!membership) return json3({ error: "tenant_access_denied" }, 403, headers);
    const result = await env.DB.prepare("SELECT id,waba_id,phone_number_id,display_phone_number,verified_name,status,created_at FROM whatsapp_connections WHERE tenant_id=? ORDER BY created_at DESC").bind(tenantId).all();
    return json3({ connections: result.results }, 200, headers);
  }
  if (path === "/api/whatsapp/connections/disconnect" && request.method === "POST") {
    const user = await sessionUser(request, env), headers = corsHeaders(request, env);
    if (!user) return json3({ error: "authentication_required" }, 401, headers);
    const body = await request.json();
    const membership = await authorizedTenant(env, user.id, body.tenant_id || "");
    if (!membership || !["owner", "church_admin"].includes(membership.role)) return json3({ error: "tenant_admin_required" }, 403, headers);
    await env.DB.prepare("UPDATE whatsapp_connections SET status='disabled',access_token_ciphertext='',token_iv='',updated_at=? WHERE id=? AND tenant_id=?").bind((/* @__PURE__ */ new Date()).toISOString(), body.connection_id || "", body.tenant_id || "").run();
    return json3({ ok: true }, 200, headers);
  }
  if (path === "/internal/whatsapp/send" && request.method === "POST") {
    const supplied = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");
    if (!env.SSO_INTERNAL_API_KEY || supplied !== env.SSO_INTERNAL_API_KEY) return json3({ error: "unauthorized" }, 401);
    const body = await request.json();
    const recipient = (body.to || "").replace(/\D/g, "");
    if (!body.tenant_id || recipient.length < 8 || recipient.length > 15) return json3({ error: "A tenant and valid international recipient number are required." }, 400);
    const isTemplate = Boolean(body.template?.name);
    if (isTemplate && !body.template?.language_code) return json3({ error: "Approved WhatsApp template name and language are required." }, 400);
    if (!isTemplate && (!body.text || body.text.length > 4096)) return json3({ error: "A text message of up to 4096 characters is required." }, 400);
    const connection = await env.DB.prepare("SELECT phone_number_id,access_token_ciphertext,token_iv FROM whatsapp_connections WHERE tenant_id=? AND status='active' ORDER BY created_at ASC LIMIT 1").bind(body.tenant_id).first();
    if (!connection) return json3({ error: "No active WhatsApp Business account is connected to this tenant." }, 409);
    const token = await decryptToken(env, connection.access_token_ciphertext, connection.token_iv);
    const payload = isTemplate ? { messaging_product: "whatsapp", recipient_type: "individual", to: recipient, type: "template", template: { name: body.template.name, language: { code: body.template.language_code }, components: body.template.components || [] } } : { messaging_product: "whatsapp", recipient_type: "individual", to: recipient, type: "text", text: { preview_url: false, body: body.text } };
    const response = await fetch("https://graph.facebook.com/" + graphVersion(env) + "/" + encodeURIComponent(connection.phone_number_id) + "/messages", {
      method: "POST",
      headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await response.json();
    if (!response.ok) return json3({ error: data.error?.message || "Meta did not accept the WhatsApp message." }, 502);
    return json3({ ok: true, providerMessageId: data.messages?.[0]?.id || null, response: data });
  }
  if (path === "/webhooks/meta/whatsapp") return handleWhatsAppWebhook(request, env);
  return json3({ error: "not_found" }, 404);
}
__name(handle, "handle");
var index_default = {
  async fetch(request, env) {
    const response = await handle(request, env);
    const headers = new Headers(response.headers);
    const cors = corsHeaders(request, env);
    for (const [key, value] of Object.entries(cors)) headers.set(key, value);
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  },
  async scheduled(_controller, env) {
    const now = /* @__PURE__ */ new Date();
    const nowIso = now.toISOString();
    const shortRetention = new Date(now.getTime() - 24 * 60 * 6e4).toISOString();
    const tokenRetention = new Date(now.getTime() - 30 * 24 * 60 * 6e4).toISOString();
    await Promise.all([
      env.DB.prepare("DELETE FROM sso_sessions WHERE expires_at<?").bind(nowIso).run(),
      env.DB.prepare("DELETE FROM sso_authorization_codes WHERE expires_at<? OR used_at<?").bind(nowIso, shortRetention).run(),
      env.DB.prepare("DELETE FROM sso_verification_challenges WHERE expires_at<? OR consumed_at<?").bind(nowIso, shortRetention).run(),
      env.DB.prepare("DELETE FROM sso_webauthn_challenges WHERE expires_at<? OR used_at<?").bind(nowIso, shortRetention).run(),
      env.DB.prepare("DELETE FROM sso_church_setup_tokens WHERE expires_at<? OR used_at<?").bind(nowIso, shortRetention).run(),
      env.DB.prepare("DELETE FROM sso_access_tokens WHERE expires_at<? OR revoked_at<?").bind(nowIso, tokenRetention).run(),
      env.DB.prepare("DELETE FROM sso_refresh_tokens WHERE expires_at<? OR revoked_at<?").bind(nowIso, tokenRetention).run(),
      env.DB.prepare("DELETE FROM sso_rate_limits WHERE expires_at<?").bind(nowIso).run()
    ]);
  }
};
export {
  index_default as default
};

