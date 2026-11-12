#!/usr/bin/env node
// did:near resolver for skjold (near-api-js 7.5.3).
//
// A did:near DID is an account id. The document exposes every FullAccess
// Ed25519 access key as one `#owner` verification method, per
// docs.near.org/primitives/didnear. Function-call keys are not identity keys,
// so they are omitted; an account with exactly one FullAccess key (the port's
// invariant for agent and issuer accounts) yields one unambiguous `#owner`.
import { JsonRpcProvider } from "near-api-js";
import { pathToFileURL } from "node:url";
import { resolveRpcUrl } from "./keys.js";

const PREFIX = "did:near:";
const CONTEXT = [
  "https://www.w3.org/ns/did/v1",
  "https://w3id.org/security/suites/ed25519-2018/v1",
];

export function buildNearDidDocument(did, keys = []) {
  const owners = keys
    .filter((key) => key?.access_key?.permission === "FullAccess")
    .filter((key) => typeof key.public_key === "string" && key.public_key.startsWith("ed25519:"))
    .map((key) => ({
      id: `${did}#owner`,
      type: "Ed25519VerificationKey2018",
      controller: did,
      publicKeyBase58: key.public_key.slice("ed25519:".length),
    }));
  return {
    "@context": CONTEXT,
    id: did,
    controller: did,
    verificationMethod: owners,
    authentication: ["#owner"],
    assertionMethod: ["#owner"],
  };
}

export async function resolveNearDid(did, options = {}) {
  if (typeof did !== "string" || !did.startsWith(PREFIX)) {
    throw new Error(`not a did:near identifier: ${did}`);
  }
  const accountId = did.slice(PREFIX.length);
  if (!accountId) throw new Error("did:near requires an account id");
  const provider =
    options.provider ??
    new JsonRpcProvider({
      url: options.rpcUrl ?? resolveRpcUrl(),
    });
  const accessKeys = await provider.viewAccessKeyList({ accountId });
  return buildNearDidDocument(did, accessKeys.keys ?? []);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const did = process.argv[2];
  if (!did) {
    console.error("usage: node sdk/src/did-near.mjs did:near:<account>");
    process.exit(2);
  }
  resolveNearDid(did)
    .then((document) => console.log(JSON.stringify(document, null, 2)))
    .catch((error) => {
      console.error(error?.message ?? String(error));
      process.exit(1);
    });
}
