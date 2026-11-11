#!/usr/bin/env node
// Signed transaction transport for the Python NearRepository adapter.
//
// One JSON request on stdin, one JSON response on stdout:
//   call: {"mode":"call","network","rpcUrl","contractId","signerId",
//          "secretKey","method","args","depositYocto","gasTgas"}
//         -> {"tx_hash":"...","status":"FINAL"}
//   view: {"mode":"view","rpcUrl","contractId","method","args"}
//         -> {"result": <decoded JSON or null>}
//
// Secret keys arrive on stdin and are never placed on the process command line.
import {
  Account,
  JsonRpcProvider,
  KeyPairSigner,
  actions,
  teraToGas,
} from "near-api-js";

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function requireString(request, field) {
  const value = request[field];
  if (typeof value !== "string" || value.length === 0) {
    fail(`request field ${field} is required`);
  }
  return value;
}

function depositYocto(value) {
  const text = String(value ?? "0");
  if (!/^\d+$/.test(text)) fail(`depositYocto must be a decimal integer, got ${text}`);
  return BigInt(text);
}

async function readStdin() {
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  try {
    return JSON.parse(raw);
  } catch {
    return fail("stdin is not valid JSON");
  }
}

const request = await readStdin();
const provider = new JsonRpcProvider({
  url: request.rpcUrl ?? process.env.NEAR_RPC_URL ?? "https://rpc.testnet.near.org",
});
const contractId = requireString(request, "contractId");
const method = requireString(request, "method");

if (request.mode === "view") {
  const result = await provider.callFunction({
    contractId,
    method,
    args: request.args ?? {},
    blockQuery: { finality: "final" },
  });
  process.stdout.write(`${JSON.stringify({ result: result ?? null })}\n`);
} else if (request.mode === "call") {
  const signerId = requireString(request, "signerId");
  const secretKey = requireString(request, "secretKey");
  const signer = KeyPairSigner.fromSecretKey(secretKey);
  const account = new Account(signerId, provider, signer);
  const gas = teraToGas(Number(request.gasTgas ?? 100));
  const action = actions.functionCall(
    method,
    request.args ?? {},
    gas,
    depositYocto(request.depositYocto),
  );
  try {
    const outcome = await account.signAndSendTransaction({
      receiverId: contractId,
      actions: [action],
      waitUntil: "FINAL",
      throwOnFailure: true,
    });
    const txHash =
      outcome?.transaction_outcome?.id ??
      outcome?.transaction?.hash ??
      outcome?.transaction?.id;
    if (!txHash) fail("transaction response omitted a hash");
    process.stdout.write(
      `${JSON.stringify({
        tx_hash: txHash,
        status: outcome?.final_execution_status ?? "FINAL",
      })}\n`,
    );
  } catch (error) {
    fail(error?.message ?? String(error));
  }
} else {
  fail('request mode must be "call" or "view"');
}
