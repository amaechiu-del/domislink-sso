import { pbkdf2Async } from "@noble/hashes/pbkdf2.js";
import { sha256 as sha256Digest } from "@noble/hashes/sha2.js";

const encoder = new TextEncoder();

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function randomToken(bytes = 32): string {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return toBase64Url(value);
}

export async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return toBase64Url(new Uint8Array(digest));
}

export async function hashPassword(password: string): Promise<string> {
  const iterations = 210_000;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await pbkdf2Async(sha256Digest, encoder.encode(password), salt, { c: iterations, dkLen: 32 });
  return `pbkdf2_sha256$${iterations}$${toBase64Url(salt)}$${toBase64Url(new Uint8Array(bits))}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4) return false;
  const [algorithm, iterationText, saltText, expectedText] = parts;
  if (algorithm !== "pbkdf2_sha256" || !iterationText || !saltText || !expectedText) return false;
  const iterations = Number(iterationText);
  if (!Number.isInteger(iterations) || iterations < 100_000 || iterations > 1_000_000) return false;
  if (!/^[A-Za-z0-9_-]{22}$/.test(saltText) || !/^[A-Za-z0-9_-]{43}$/.test(expectedText)) return false;
  const salt = fromBase64Url(saltText);
  const expected = fromBase64Url(expectedText);
  const bits = await pbkdf2Async(sha256Digest, encoder.encode(password), salt, { c: iterations, dkLen: expected.length });
  if (bits.length !== expected.length) return false;
  let difference = 0;
  for (let i = 0; i < bits.length; i++) difference |= bits[i] ^ expected[i];
  return difference === 0;
}

export function readCookie(header: string | undefined, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) {
      try { return decodeURIComponent(part.slice(separator + 1).trim()); }
      catch { return null; }
    }
  }
  return null;
}

export function sessionCookie(token: string, maxAgeSeconds: number): string {
  return `dl_church_session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}`;
}

export const clearSessionCookie =
  "dl_church_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
