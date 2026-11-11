#!/usr/bin/env node
// Recompute the skjold-vc-digest/v1 credential digest (verifier helper).
//
//   node sdk/scripts/recompute-vc-digest.mjs credential.json
//   cat credential.json | node sdk/scripts/recompute-vc-digest.mjs
//
// digest = Base64(sha256(canonicalize_json(vc - proof - credentialStatus)))
//
// The canonical form is the project profile from spec/verify/v1/README.md
// (attestix/auth/crypto.py), NOT strict RFC 8785:
//   * every string value and object key is NFC-normalized;
//   * object keys sort by Unicode code point, recursively;
//   * whole-number floats collapse to integers; non-finite numbers are rejected;
//   * keys that collide after NFC normalization are rejected;
//   * JSON uses "," and ":" separators with raw UTF-8 (no escape sequences for non-ASCII);
//   * integers are arbitrary precision (JSON integer tokens become BigInt).
//
// Label: skjold-vc-digest/v1. This is not the stock did:near ProofType cid,
// which hashes the whole credential; the two are not interchangeable.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const PROFILE = "skjold-vc-digest/v1";

function compareCodePoints(left, right) {
  const a = [...left];
  const b = [...right];
  const length = Math.min(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const delta = a[index].codePointAt(0) - b[index].codePointAt(0);
    if (delta !== 0) return delta;
  }
  return a.length - b.length;
}

function parseJson(text) {
  // JSON.parse source-text access (Node >= 21) preserves integer tokens beyond
  // 2^53 as BigInt instead of silently rounding them.
  return JSON.parse(text, (key, value, context) => {
    if (typeof value === "number") {
      const source = context?.source;
      if (typeof source === "string" && !/[.eE]/.test(source) && /^-?\d+$/.test(source)) {
        return BigInt(source);
      }
    }
    return value;
  });
}

function normalize(value) {
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

function canonicalize(credential) {
  const payload = {};
  for (const [key, value] of Object.entries(credential)) {
    if (key === "proof" || key === "credentialStatus") continue;
    payload[key] = value;
  }
  return Buffer.from(serialize(normalize(payload)), "utf8");
}

function readInput() {
  const argument = process.argv[2];
  if (argument && argument !== "-") {
    if (argument.trimStart().startsWith("{")) return argument;
    return readFileSync(argument, "utf8");
  }
  return readFileSync(0, "utf8");
}

let credential;
try {
  credential = parseJson(readInput());
} catch (error) {
  process.stderr.write(`cannot read credential JSON: ${error.message}\n`);
  process.exit(1);
}
if (credential === null || typeof credential !== "object" || Array.isArray(credential)) {
  process.stderr.write("credential JSON must be an object\n");
  process.exit(1);
}

try {
  const canonical = canonicalize(credential);
  const digest = createHash("sha256").update(canonical).digest("base64");
  process.stdout.write(
    `${JSON.stringify({ digest, profile: PROFILE, canonical_bytes: canonical.length })}\n`,
  );
} catch (error) {
  process.stderr.write(`cannot canonicalize credential: ${error.message}\n`);
  process.exit(1);
}
