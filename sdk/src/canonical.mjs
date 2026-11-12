// skjold canonical JSON profile (label `skjold-vc-digest/v1`).
//
// This is the same project profile implemented by
// `sdk/scripts/recompute-vc-digest.mjs` and `attestix/auth/crypto.py`, NOT strict
// RFC 8785:
//   * every string value and object key is NFC-normalized;
//   * object keys sort by Unicode code point, recursively;
//   * whole-number floats collapse to integers; non-finite numbers are rejected;
//   * keys that collide after NFC normalization are rejected;
//   * JSON uses "," and ":" separators with raw UTF-8 (non-ASCII is not escaped);
//   * integers are arbitrary precision (BigInt is emitted as a bare integer token).
//
// Canonicalization is only used off-chain for signatures and digests; contract
// arguments are a separate wire concern (see `demo.js`).
import { createHash } from "node:crypto";

/** UAIT fields that never enter `uait_digest` (origin `IdentityService.MUTABLE_FIELDS`). */
export const UAIT_MUTABLE_FIELDS = Object.freeze(
  new Set(["signature", "revoked", "revocation_reason", "revoked_at", "reputation_score", "eu_compliance"]),
);

/** Credential fields excluded from the `skjold-vc-digest/v1` payload. */
export const VC_MUTABLE_FIELDS = Object.freeze(new Set(["proof", "credentialStatus"]));

export function compareCodePoints(left, right) {
  const a = [...left];
  const b = [...right];
  const length = Math.min(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const delta = a[index].codePointAt(0) - b[index].codePointAt(0);
    if (delta !== 0) return delta;
  }
  return a.length - b.length;
}

export function normalize(value) {
  if (typeof value === "string") return value.normalize("NFC");
  if (typeof value === "boolean" || value === null) return value;
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("JSON numbers must be finite");
    if (Number.isInteger(value)) return BigInt(value);
    return value;
  }
  if (Array.isArray(value)) return value.map(normalize);
  if (typeof value === "object") {
    const entries = [];
    const seen = new Set();
    for (const [rawKey, rawValue] of Object.entries(value)) {
      if (typeof rawKey !== "string") {
        throw new Error("JSON object keys must be strings");
      }
      const key = rawKey.normalize("NFC");
      if (seen.has(key)) {
        throw new Error("JSON object keys collide after NFC normalization");
      }
      seen.add(key);
      entries.push([key, normalize(rawValue)]);
    }
    entries.sort(([a], [b]) => compareCodePoints(a, b));
    return new Map(entries);
  }
  throw new Error(`unsupported JSON value: ${typeof value}`);
}

function formatFloat(value) {
  if (!Number.isFinite(value)) throw new Error("JSON numbers must be finite");
  const magnitude = Math.abs(value);
  // Python repr uses scientific notation outside [1e-4, 1e16).
  if (magnitude !== 0 && (magnitude >= 1e16 || magnitude < 1e-4)) {
    return value.toExponential().replace(/e([+-])(\d)$/, "e$10$2");
  }
  return value.toString();
}

function serialize(value) {
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "number") return formatFloat(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (value === null) return "null";
  if (Array.isArray(value)) return `[${value.map(serialize).join(",")}]`;
  if (value instanceof Map) {
    const fields = [...value.entries()].map(
      ([key, item]) => `${JSON.stringify(key)}:${serialize(item)}`,
    );
    return `{${fields.join(",")}}`;
  }
  throw new Error("unsupported normalized value");
}

/**
 * Canonical UTF-8 bytes of a JSON object, excluding top-level keys in
 * `excludedKeys` (the recompute script drops `proof`/`credentialStatus`, the
 * identity path drops the UAIT mutable fields).
 */
export function canonicalizeJson(value, excludedKeys = []) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("canonicalizeJson requires a JSON object");
  }
  const excluded =
    excludedKeys instanceof Set ? excludedKeys : new Set(Array.isArray(excludedKeys) ? excludedKeys : []);
  const payload = {};
  for (const [key, item] of Object.entries(value)) {
    if (excluded.has(key)) continue;
    payload[key] = item;
  }
  return Buffer.from(serialize(normalize(payload)), "utf8");
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest();
}

/**
 * Contract capability digest: `sha256` of the sorted capability list as compact
 * JSON (`json.dumps(sorted(...), separators=(",", ":"), ensure_ascii=False)`).
 */
export function capabilitiesDigest(capabilities) {
  const sorted = [...capabilities].map(String).sort(compareCodePoints);
  return sha256(Buffer.from(JSON.stringify(sorted), "utf8"));
}

/** Standard Base64 (the cid wire/DID-string form, not base64url). */
export function digestBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

/** base64url WITH padding: `python base64.urlsafe_b64encode` (the proof profile). */
export function base64UrlWithPadding(bytes) {
  return Buffer.from(bytes)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_");
}

/**
 * `Digest32` as the contract's W2 JSON wire form: a 32-number array.
 * Standard Base64 remains the display/DID-string form.
 */
export function toWireDigest(bytes) {
  const raw = Buffer.from(bytes);
  if (raw.length !== 32) {
    throw new Error(`Digest32 must be 32 bytes, got ${raw.length}`);
  }
  return Array.from(raw);
}

/** Accept either wire form a future contract revision may return. */
export function digestFromJson(value) {
  if (Array.isArray(value) && value.length === 32) return Buffer.from(value);
  if (typeof value === "string") {
    const raw = Buffer.from(value, "base64");
    if (raw.length === 32) return raw;
  }
  return null;
}
