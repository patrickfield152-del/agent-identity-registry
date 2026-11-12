#!/usr/bin/env node
// Zero-funds skjold demo on NEAR (near-api-js 7.5.3).
//
//   node sdk/src/demo.js
//
// One run exercises the registry end to end with no funded counterparties:
//   1. load config, create a fresh agent keypair and the canonical UAIT digest
//   2. create_agent on the operator (25 mN deposit, callback polled to FINAL)
//   3. issue a W3C VC, sign it with the issuer key and anchor its cid
//   4. record_delegation (jti + FCK public key + capabilities digest)
//   5. install the FCK on the agent account, scoped to `anchor_artifact`
//   6. anchor an artifact AS THE AGENT through the FCK
//   7. record two interactions as the operator, then verify reputation,
//      credential validity and the did:near document
//   8. revoke the delegation as the operator
//   9. prove the next FCK call is refused BY THE REGISTRY and that
//      get_delegation(jti).revoked === true
//
// Required environment (see .env.example):
//   SKJOLD_REGISTRY_ID        registry contract account (operator defaults to it)
//   SKJOLD_OPERATOR_KEY       operator full-access secret key (`ed25519:...`)
//   SKJOLD_VC_ISSUER_KEY      issuer secret key; the issuer account's only FA key
// Optional:
//   SKJOLD_OPERATOR_ACCOUNT   signer account (default: the registry account)
//   SKJOLD_VC_ISSUER_ACCOUNT  issuer did:near account (default: vc-issuer.<registry>)
//   NEAR_RPC_URL              explicit RPC endpoint
//   NEAR_NETWORK              `testnet` (default) or `mainnet`
//
// Codes are printed to stderr; stdout carries exactly one JSON summary. Secret
// keys are never logged. A failed step throws and exits non-zero; the demo never
// reports success without the real contract calls below.
import { randomBytes, randomUUID } from "node:crypto";
import { sleep } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import {
  Account,
  JsonRpcProvider,
  KeyPair,
  KeyPairSigner,
  actions,
  nearToYocto,
  teraToGas,
} from "near-api-js";
import { resolveNearDid } from "./did-near.mjs";
import { addFunctionCallAccessKey, FCK_METHOD_NAMES } from "./keys.js";
import {
  UAIT_MUTABLE_FIELDS,
  VC_MUTABLE_FIELDS,
  base64UrlWithPadding,
  canonicalizeJson,
  capabilitiesDigest,
  digestFromJson,
  sha256,
  toWireDigest,
} from "./canonical.mjs";

const NETWORK_DEFAULT_RPC = {
  testnet: "https://rpc.testnet.near.org",
  mainnet: "https://rpc.mainnet.near.org",
};

// create_agent forwards 10 mN to the sub-account, the registry pays the 7 mN
// CreateAccount charge, and the operator prepays 50 mN of agent storage credit
// for zero-deposit FCK anchors; the contract refunds the excess. 0.1 N covers
// all of that plus the record.
const CREATE_AGENT_DEPOSIT = nearToYocto("0.1");
// Every other growing method bills `storage_byte_cost x borsh bytes` and refunds
// the excess. 5 mN covers each record in this flow with room to spare.
const GROWTH_DEPOSIT = nearToYocto("0.005");
const CALL_GAS = teraToGas(100);

const IDENTITY_POLL_ATTEMPTS = 20;
const IDENTITY_POLL_INTERVAL_MS = 1500;

const DISPLAY_NAME = "Skjold Demo Agent";
const DESCRIPTION = "Zero-funds demo agent created by sdk/src/demo.js";
const SOURCE_PROTOCOL = "mcp";
const ISSUER_NAME = "Skjold Demo Issuer";
const VC_TYPE = "AgentIdentityCredential";
// UAIT capabilities advertised by the new agent.
const CAPABILITIES = ["anchor_artifact", "credential-verify"];
// The delegation's capability set is exactly the FCK's registry scope.
const DELEGATION_CAPABILITIES = [...FCK_METHOD_NAMES];
const FCK_ALLOWANCE = nearToYocto("0.25");

class RefusalNotObserved extends Error {}

function log(message) {
  process.stderr.write(`${message}\n`);
}

function errorText(error) {
  const parts = [];
  if (error?.message) parts.push(error.message);
  if (error?.transactionResult) {
    try {
      parts.push(JSON.stringify(error.transactionResult.status ?? error.transactionResult));
    } catch {
      parts.push("[unserializable transactionResult]");
    }
  }
  if (parts.length === 0) parts.push(String(error));
  return parts.join(" | ");
}

function fail(message) {
  throw new Error(message);
}

function loadConfig() {
  const env = process.env;
  const registryId = (env.SKJOLD_REGISTRY_ID ?? "").trim();
  const operatorAccountId = (env.SKJOLD_OPERATOR_ACCOUNT ?? "").trim() || registryId;
  const issuerAccountId =
    (env.SKJOLD_VC_ISSUER_ACCOUNT ?? "").trim() ||
    (registryId ? `vc-issuer.${registryId}` : "");
  const operatorKey = (env.SKJOLD_OPERATOR_KEY ?? "").trim();
  const issuerKey = (env.SKJOLD_VC_ISSUER_KEY ?? "").trim();
  const network = (env.NEAR_NETWORK ?? "testnet").trim().toLowerCase();
  const rpcUrl =
    (env.NEAR_RPC_URL ?? "").trim() ||
    NETWORK_DEFAULT_RPC[network] ||
    NETWORK_DEFAULT_RPC.testnet;

  const missing = [];
  if (!registryId) missing.push("SKJOLD_REGISTRY_ID");
  if (!operatorKey) missing.push("SKJOLD_OPERATOR_KEY");
  if (!issuerKey) missing.push("SKJOLD_VC_ISSUER_KEY");
  if (missing.length > 0) {
    fail(
      `missing required environment variable(s): ${missing.join(", ")}\n` +
        "set SKJOLD_REGISTRY_ID, SKJOLD_OPERATOR_KEY and SKJOLD_VC_ISSUER_KEY " +
        "(optional: SKJOLD_OPERATOR_ACCOUNT, SKJOLD_VC_ISSUER_ACCOUNT, NEAR_RPC_URL, NEAR_NETWORK)",
    );
  }
  if (!operatorAccountId) fail("SKJOLD_OPERATOR_ACCOUNT is empty (the operator signer needs an account)");
  if (!issuerAccountId) fail("SKJOLD_VC_ISSUER_ACCOUNT is empty (the issuer DID needs an account)");

  return {
    registryId,
    operatorAccountId,
    issuerAccountId,
    operatorKey,
    issuerKey,
    network,
    rpcUrl,
    issuerDid: `did:near:${issuerAccountId}`,
  };
}

function parseSecretKey(secretKey, variableName) {
  let keyPair;
  try {
    keyPair = KeyPair.fromString(secretKey);
  } catch {
    // Never echo the key material.
    fail(`${variableName} is not a valid near-api-js secret key (expected "ed25519:<base58>")`);
  }
  if (!keyPair.getPublicKey().toString().startsWith("ed25519:")) {
    fail(`${variableName} must be an ed25519 key (the did:near and VC profiles are Ed25519)`);
  }
  return keyPair;
}

function txHash(result) {
  return (
    result?.transaction_outcome?.id ??
    result?.transaction?.hash ??
    result?.transaction?.id ??
    null
  );
}

function executionFailure(outcome) {
  const status = outcome?.status;
  if (status && typeof status === "object" && "Failure" in status) return status.Failure;
  return null;
}

// JSON args with exact `u64`/BigInt tokens. `JSON.stringify` would round
// nanosecond timestamps past 2^53; the contract's u64 deserializer needs a bare
// JSON integer, not a string. Digest32 stays the W2 wire form (32 numbers).
function encodeArgs(value) {
  return new TextEncoder().encode(serializeArg(value));
}

function serializeArg(value) {
  if (typeof value === "bigint") return value.toString();
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("contract arguments must use finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(serializeArg).join(",")}]`;
  }
  if (typeof value === "object") {
    const fields = [];
    for (const [key, item] of Object.entries(value)) {
      if (item === undefined) continue;
      fields.push(`${JSON.stringify(key)}:${serializeArg(item)}`);
    }
    return `{${fields.join(",")}}`;
  }
  throw new Error(`unsupported contract argument: ${typeof value}`);
}

async function view(provider, contractId, method, args) {
  return provider.callFunction({
    contractId,
    method,
    args,
    blockQuery: { finality: "final" },
  });
}

async function submit(account, receiverId, method, args, deposit) {
  const outcome = await account.signAndSendTransaction({
    receiverId,
    actions: [actions.functionCall(method, encodeArgs(args), CALL_GAS, deposit)],
    waitUntil: "FINAL",
    throwOnFailure: true,
  });
  const hash = txHash(outcome);
  if (!hash) fail(`${method} returned a final outcome without a transaction hash`);
  return {
    tx_hash: hash,
    status: outcome?.final_execution_status ?? "FINAL",
    outcome,
  };
}

async function sendCall(account, receiverId, method, args, deposit, label) {
  try {
    const result = await submit(account, receiverId, method, args, deposit);
    log(`    tx ${result.tx_hash} (${method})`);
    return result;
  } catch (error) {
    throw new Error(`${label}: ${method} failed: ${errorText(error)}`);
  }
}

function makePrefix() {
  // Contract rule: 1-32 chars of [a-z0-9-_], no leading/trailing '-'.
  return `agent-demo-${randomBytes(4).toString("hex")}`;
}

function isoFromMs(ms) {
  return new Date(ms).toISOString();
}

function buildUait({ agentId, issuer, createdIso, expiresIso }) {
  const uait = {
    version: "0.1.0",
    agent_id: agentId,
    agent: agentId,
    did: issuer.did,
    display_name: DISPLAY_NAME,
    description: DESCRIPTION,
    source_protocol: SOURCE_PROTOCOL,
    identity_token: "",
    token_info: {},
    capabilities: [...CAPABILITIES],
    issuer: { name: ISSUER_NAME, did: issuer.did },
    created_at: createdIso,
    expires_at: expiresIso,
    revoked: false,
    revocation_reason: null,
    reputation_score: null,
    eu_compliance: null,
    signature: null,
  };
  // `uait_digest = sha256(canonicalize_json(UAIT - MUTABLE_FIELDS))`; the
  // signature field is excluded, so signing the same payload does not move it.
  const signedPayload = canonicalizeJson(uait, UAIT_MUTABLE_FIELDS);
  const digest = sha256(signedPayload);
  const signature = issuer.keyPair.sign(signedPayload);
  uait.signature = base64UrlWithPadding(signature.signature);
  return { uait, uaitDigest: digest };
}

function buildCredential({ agentId, agentDid, issuer, createdIso, expiresIso }) {
  const credential = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: `urn:uuid:${randomUUID()}`,
    type: ["VerifiableCredential", VC_TYPE],
    issuer: { id: issuer.did, name: ISSUER_NAME },
    issuanceDate: createdIso,
    expirationDate: expiresIso,
    credentialSubject: {
      id: agentDid,
      accountId: agentId,
      displayName: DISPLAY_NAME,
    },
  };
  const payload = canonicalizeJson(credential, VC_MUTABLE_FIELDS);
  const signature = issuer.keyPair.sign(payload);
  const proof = {
    type: "Ed25519Signature2020",
    created: createdIso,
    verificationMethod: `${issuer.did}#owner`,
    proofPurpose: "assertionMethod",
    proofValue: base64UrlWithPadding(signature.signature),
  };
  credential.proof = proof;
  return { credential, proof, cid: sha256(payload) };
}

async function verifyIssuerKey(provider, issuerAccountId, issuerKeyPair) {
  const listing = await provider.viewAccessKeyList({ accountId: issuerAccountId });
  const fullAccess = (listing.keys ?? []).filter(
    (entry) =>
      entry?.access_key?.permission === "FullAccess" &&
      typeof entry.public_key === "string" &&
      entry.public_key.startsWith("ed25519:"),
  );
  if (fullAccess.length !== 1) {
    fail(
      `issuer ${issuerAccountId} must hold exactly one FullAccess ed25519 key ` +
        `(found ${fullAccess.length}); did:near needs one unambiguous #owner fragment`,
    );
  }
  const expected = issuerKeyPair.getPublicKey().toString();
  if (fullAccess[0].public_key !== expected) {
    fail(`SKJOLD_VC_ISSUER_KEY does not match the single FullAccess key of ${issuerAccountId}`);
  }
  return expected;
}

async function waitForIdentity(provider, registryId, agentId, expectedDigest, createTxHash) {
  const deadlineMs = IDENTITY_POLL_ATTEMPTS * IDENTITY_POLL_INTERVAL_MS;
  let lastError = null;
  for (let attempt = 1; attempt <= IDENTITY_POLL_ATTEMPTS; attempt += 1) {
    if (attempt > 1) await sleep(IDENTITY_POLL_INTERVAL_MS);
    let record = null;
    try {
      record = await view(provider, registryId, "get_identity", { agent: agentId });
    } catch (error) {
      lastError = errorText(error);
      continue;
    }
    if (!record) continue;
    if (record.agent !== agentId) {
      fail(`get_identity(${agentId}) returned a record for ${record.agent}`);
    }
    const landedDigest = digestFromJson(record.uait_digest);
    if (!landedDigest || !landedDigest.equals(expectedDigest)) {
      fail(`get_identity(${agentId}) landed with a different uait_digest`);
    }
    return record;
  }
  fail(
    `get_identity(${agentId}) did not land within ${deadlineMs} ms ` +
      `(${IDENTITY_POLL_ATTEMPTS} attempts x ${IDENTITY_POLL_INTERVAL_MS} ms) ` +
      `after create_agent tx ${createTxHash}` +
      (lastError ? `; last view error: ${lastError}` : ""),
  );
}

async function expectDelegationRefusal(fckAccount, registryId, args) {
  let rejection;
  try {
    const result = await submit(fckAccount, registryId, "anchor_artifact", args, GROWTH_DEPOSIT);
    const failure = executionFailure(result.outcome);
    if (!failure) {
      throw new RefusalNotObserved(
        `anchor_artifact SUCCEEDED after revoke_delegation (tx ${result.tx_hash}); ` +
          "the registry did not refuse the revoked FCK",
      );
    }
    rejection = { error: JSON.stringify(failure), tx_hash: result.tx_hash };
  } catch (error) {
    if (error instanceof RefusalNotObserved) throw error;
    rejection = {
      error: errorText(error),
      tx_hash: error?.transactionResult ? txHash(error.transactionResult) : null,
    };
  }
  if (!rejection.error.toLowerCase().includes("delegation revoked")) {
    // A nonce/key error would also be a failure; only the registry's delegation
    // check is the expected cut-off.
    throw new Error(
      `post-revocation anchor_artifact failed, but not with the registry's ` +
        `"delegation revoked" refusal: ${rejection.error}`,
    );
  }
  return {
    method: "anchor_artifact",
    expected: "delegation revoked",
    rejected: true,
    tx_hash: rejection.tx_hash,
    error: rejection.error,
  };
}

async function main() {
  const steps = [];
  const mark = (step, title) => {
    steps.push({ step, title });
    log(`[${step}/9] ${title}`);
  };

  mark(
    1,
    "config + fresh agent keypair + canonical UAIT digest",
  );
  const config = loadConfig();
  const provider = new JsonRpcProvider({ url: config.rpcUrl });
  const operatorKeyPair = parseSecretKey(config.operatorKey, "SKJOLD_OPERATOR_KEY");
  const issuerKeyPair = parseSecretKey(config.issuerKey, "SKJOLD_VC_ISSUER_KEY");
  const operatorSigner = new KeyPairSigner(operatorKeyPair);

  const issuer = { account: config.issuerAccountId, did: config.issuerDid, keyPair: issuerKeyPair };
  const issuerOnChainKey = await verifyIssuerKey(provider, issuer.account, issuer.keyPair);
  log(`    issuer ${issuer.did} resolves to its single FullAccess key`);

  const agentKeyPair = KeyPair.fromRandom("ed25519");
  const agentPublicKey = agentKeyPair.getPublicKey();
  const agentPublicKeyString = agentPublicKey.toString();
  const prefix = makePrefix();
  const agentId = `${prefix}.${config.registryId}`;
  const agentDid = `did:near:${agentId}`;
  const agentSigner = KeyPairSigner.fromSecretKey(agentKeyPair.toString());
  const agentAccount = new Account(agentId, provider, agentSigner);

  const nowMs = Date.now();
  const expiresMs = nowMs + 365 * 24 * 60 * 60 * 1000;
  const createdIso = isoFromMs(nowMs);
  const expiresIso = isoFromMs(expiresMs);
  const expiresAtNs = BigInt(expiresMs) * 1_000_000n;

  const { uaitDigest } = buildUait({
    agentId,
    issuer,
    createdIso,
    expiresIso,
  });
  log(`    agent ${agentDid}`);
  log(`    uait_digest ${uaitDigest.toString("base64")}`);

  mark(2, "create_agent + wait for the on_agent_created callback");
  const operatorAccount = new Account(config.operatorAccountId, provider, operatorSigner);
  const createResult = await sendCall(
    operatorAccount,
    config.registryId,
    "create_agent",
    {
      prefix,
      full_access_key: agentPublicKeyString,
      uait_digest: toWireDigest(uaitDigest),
      display_name: DISPLAY_NAME,
      description: DESCRIPTION,
      source_protocol: SOURCE_PROTOCOL,
      issuer_name: ISSUER_NAME,
      issuer_did: issuer.did,
      capabilities: [...CAPABILITIES],
      expires_at_ns: expiresAtNs,
    },
    CREATE_AGENT_DEPOSIT,
    "step 2",
  );
  const identityRecord = await waitForIdentity(
    provider,
    config.registryId,
    agentId,
    uaitDigest,
    createResult.tx_hash,
  );
  log(`    get_identity landed after FINAL (created_at_ns ${identityRecord.created_at_ns})`);

  // `create_agent` forwards only 10 mN to the new sub-account. The agent's own
  // FCK transaction must prepay gas and attach a storage deposit, so fund it
  // from the operator (testnet faucet funds; no real funds involved). The
  // agent's only FullAccess key is unchanged.
  const fundingOutcome = await operatorAccount.signAndSendTransaction({
    receiverId: agentId,
    actions: [actions.transfer(nearToYocto("0.1"))],
    waitUntil: "FINAL",
    throwOnFailure: true,
  });
  const fundingTxHash = txHash(fundingOutcome);
  if (!fundingTxHash) fail("agent funding transfer returned no transaction hash");
  log(`    funded agent with 0.1 N for its own FCK call (tx ${fundingTxHash})`);

  mark(3, "issue W3C VC + anchor its skjold-vc-digest/v1 cid");
  const { credential, proof, cid } = buildCredential({
    agentId,
    agentDid,
    issuer,
    createdIso,
    expiresIso,
  });
  const anchorCredentialResult = await sendCall(
    operatorAccount,
    config.registryId,
    "anchor_credential",
    {
      subject_did: agentDid,
      subject_account: agentId,
      cid: toWireDigest(cid),
      cred_type: VC_TYPE,
      expires_at_ns: expiresAtNs,
    },
    GROWTH_DEPOSIT,
    "step 3",
  );
  log(`    cid ${cid.toString("base64")}`);
  log(`    proof ${proof.type} ${proof.verificationMethod}`);

  mark(4, "record_delegation (jti + FCK + capabilities digest)");
  const fckKeyPair = KeyPair.fromRandom("ed25519");
  const fckPublicKey = fckKeyPair.getPublicKey();
  const fckPublicKeyString = fckPublicKey.toString();
  const delegationCapabilitiesHash = capabilitiesDigest(DELEGATION_CAPABILITIES);
  const jti = `urn:uuid:${randomUUID()}`;
  const recordDelegationResult = await sendCall(
    operatorAccount,
    config.registryId,
    "record_delegation",
    {
      jti,
      agent: agentId,
      audience: agentId,
      capabilities_hash: toWireDigest(delegationCapabilitiesHash),
      fck_pubkey: fckPublicKeyString,
      parent_jti: null,
      expires_at_ns: 0n,
    },
    GROWTH_DEPOSIT,
    "step 4",
  );
  log(`    jti ${jti}`);
  log(`    fck ${fckPublicKeyString}`);

  mark(5, "install the FCK on the agent account (scoped to anchor_artifact)");
  const fckKeyResult = await addFunctionCallAccessKey(agentAccount, fckPublicKey, {
    contractId: config.registryId,
    methodNames: [...DELEGATION_CAPABILITIES],
    allowance: FCK_ALLOWANCE,
  });
  const fckKeyTxHash = txHash(fckKeyResult);
  if (!fckKeyTxHash) fail("AddKey transaction returned no hash");
  log(`    tx ${fckKeyTxHash} (AddKey, signed by the agent FullAccess key)`);

  mark(6, "anchor_artifact AS THE AGENT through the FCK");
  const artifactId = `urn:uuid:${randomUUID()}`;
  const artifactDigest = sha256(Buffer.from(`${agentId}:${artifactId}`, "utf8"));
  const fckAccount = new Account(
    agentId,
    provider,
    KeyPairSigner.fromSecretKey(fckKeyPair.toString()),
  );
  const anchorArtifactResult = await sendCall(
    fckAccount,
    config.registryId,
    "anchor_artifact",
    {
      artifact_digest: toWireDigest(artifactDigest),
      artifact_type: "Declaration",
      artifact_id: artifactId,
      subject_account: null,
    },
    0n,
    "step 6",
  );
  log(`    artifact ${artifactId}`);

  // A function-call key cannot attach a deposit; the registry debits the
  // agent's prepaid 50 mN storage credit instead.
  const storageCreditAfter = await view(provider, config.registryId, "get_storage_credit", {
    agent: agentId,
  });
  log(`    storage credit remaining ${storageCreditAfter} yoctoNEAR`);

  mark(7, "record interactions as operator + verify reputation, credential, did:near");
  const counterpartyAccountId = config.issuerAccountId;
  const runId = randomBytes(4).toString("hex");
  const interactions = [];
  for (const outcome of ["success", "partial"]) {
    const interactionId = `demo-${runId}-${outcome}`;
    const result = await sendCall(
      operatorAccount,
      config.registryId,
      "record_interaction",
      {
        agent: agentId,
        counterparty: counterpartyAccountId,
        interaction_id: interactionId,
        outcome,
        category: "demo",
        details: `zero-funds demo ${outcome} interaction`,
      },
      GROWTH_DEPOSIT,
      "step 7",
    );
    interactions.push({ interaction_id: interactionId, outcome, tx_hash: result.tx_hash });
  }

  const reputation = await view(provider, config.registryId, "get_reputation", {
    agent: agentId,
  });
  if (!reputation || typeof reputation.trust_score !== "number") {
    fail(`get_reputation(${agentId}) returned no trust score`);
  }
  if (reputation.total_interactions < interactions.length) {
    fail(
      `get_reputation(${agentId}) total_interactions=${reputation.total_interactions}, ` +
        `expected at least ${interactions.length}`,
    );
  }

  const credentialValid = await view(provider, config.registryId, "is_credential_valid", {
    cid: toWireDigest(cid),
  });
  if (credentialValid !== true) {
    fail(`is_credential_valid(${cid.toString("base64")}) returned ${JSON.stringify(credentialValid)}`);
  }

  const didDocument = await resolveNearDid(agentDid, { provider });
  const verificationMethods = didDocument.verificationMethod ?? [];
  if (verificationMethods.length !== 1) {
    fail(
      `${agentDid} must resolve to exactly one #owner verification method ` +
        `(found ${verificationMethods.length})`,
    );
  }
  if (verificationMethods[0].id !== `${agentDid}#owner`) {
    fail(`${agentDid} owner id is ${verificationMethods[0].id}, expected ${agentDid}#owner`);
  }
  const expectedBase58 = agentPublicKeyString.slice("ed25519:".length);
  if (verificationMethods[0].publicKeyBase58 !== expectedBase58) {
    fail(`${agentDid} owner key does not match the agent's FullAccess key`);
  }
  log(`    trust_score ${reputation.trust_score} over ${reputation.total_interactions} interaction(s)`);

  mark(8, "revoke_delegation (registry cut-off)");
  const revokeResult = await sendCall(
    operatorAccount,
    config.registryId,
    "revoke_delegation",
    {
      jti,
      reason: "demo: delegation revoked at the end of the flow",
    },
    GROWTH_DEPOSIT,
    "step 8",
  );

  mark(9, "next FCK call refused by the registry + get_delegation().revoked");
  const refusedArtifactId = `urn:uuid:${randomUUID()}`;
  const refusedDigest = sha256(Buffer.from(`${agentId}:${refusedArtifactId}`, "utf8"));
  const refusal = await expectDelegationRefusal(fckAccount, config.registryId, {
    artifact_digest: toWireDigest(refusedDigest),
    artifact_type: "Declaration",
    artifact_id: refusedArtifactId,
    subject_account: null,
  });
  log(`    refused as expected: ${refusal.error}`);

  const delegation = await view(provider, config.registryId, "get_delegation", { jti });
  if (!delegation) fail(`get_delegation(${jti}) returned nothing after revoke_delegation`);
  if (delegation.revoked !== true) {
    fail(`get_delegation(${jti}).revoked is ${JSON.stringify(delegation.revoked)}, expected true`);
  }

  const summary = {
    profile: "skjold-vc-digest/v1",
    network: config.network,
    rpc_url: config.rpcUrl,
    registry_id: config.registryId,
    operator_account: config.operatorAccountId,
    issuer: {
      account: issuer.account,
      did: issuer.did,
      full_access_key: issuerOnChainKey,
      key_matches_on_chain: true,
    },
    agent: {
      account: agentId,
      did: agentDid,
      prefix,
      full_access_key: agentPublicKeyString,
      uait_digest_b64: uaitDigest.toString("base64"),
      expires_at_ns: expiresAtNs.toString(),
    },
    steps,
    identity: {
      create_tx_hash: createResult.tx_hash,
      status: createResult.status,
      callback_landed: true,
      created_at_ns: String(identityRecord.created_at_ns),
      storage_credit_yocto: storageCreditAfter,
    },
    credential: {
      id: credential.id,
      type: credential.type,
      issuer: credential.issuer,
      subject: credential.credentialSubject.id,
      cid_b64: cid.toString("base64"),
      proof: {
        type: proof.type,
        verificationMethod: proof.verificationMethod,
        proofPurpose: proof.proofPurpose,
      },
      anchor_tx_hash: anchorCredentialResult.tx_hash,
      valid_on_chain: credentialValid,
      expires_at_ns: expiresAtNs.toString(),
    },
    delegation: {
      jti,
      agent: agentId,
      audience: agentId,
      fck_public_key: fckPublicKeyString,
      capabilities: [...DELEGATION_CAPABILITIES],
      capabilities_hash_b64: delegationCapabilitiesHash.toString("base64"),
      record_tx_hash: recordDelegationResult.tx_hash,
      key_install_tx_hash: fckKeyTxHash,
      revoked: delegation.revoked,
      revoke_tx_hash: revokeResult.tx_hash,
    },
    artifact: {
      artifact_id: artifactId,
      artifact_digest_b64: artifactDigest.toString("base64"),
      anchored_as: agentId,
      tx_hash: anchorArtifactResult.tx_hash,
    },
    interactions,
    reputation: {
      trust_score: reputation.trust_score,
      total_interactions: reputation.total_interactions,
      last_interaction_ns: String(reputation.last_interaction_ns ?? 0),
    },
    did_document: {
      id: didDocument.id,
      verification_method: verificationMethods[0].id,
      public_key_base58: verificationMethods[0].publicKeyBase58,
    },
    refusal,
  };

  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`demo failed: ${errorText(error)}\n`);
    if (process.env.SKJOLD_DEMO_STACK === "1" && error?.stack) {
      process.stderr.write(`${error.stack}\n`);
    }
    process.exitCode = 1;
  });
}
