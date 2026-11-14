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
import { readFileSync } from "node:fs";
import {
  VC_MUTABLE_FIELDS,
  canonicalizeJson,
  digestBase64,
  sha256,
} from "../src/canonical.mjs";

const PROFILE = "skjold-vc-digest/v1";

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
  const canonical = canonicalizeJson(credential, VC_MUTABLE_FIELDS);
  const digest = digestBase64(sha256(canonical));
  process.stdout.write(
    `${JSON.stringify({ digest, profile: PROFILE, canonical_bytes: canonical.length })}\n`,
  );
} catch (error) {
  process.stderr.write(`cannot canonicalize credential: ${error.message}\n`);
  process.exit(1);
}
