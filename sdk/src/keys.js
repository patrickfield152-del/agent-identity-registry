// Delegation key helpers for skjold (near-api-js 7.5.3).
//
// A delegation is a scoped FunctionCall access key on the AGENT account:
//   contractId: SKJOLD_REGISTRY_ID
//   methodNames: ["anchor_artifact"]   (the only agent-callable registry path)
//   allowance: nearToYocto("0.25")     (gas-only budget; not a spend cap)
//
// The allowance CANNOT be changed in place (nomicon FunctionCallPermission);
// re-issue the delegation by deleting the old key and adding a new one. The
// registry flag from revoke_delegation is the authoritative cut-off; deleteKey
// is hygiene.
import {
  Account,
  JsonRpcProvider,
  KeyPairSigner,
  actions,
  nearToYocto,
} from "near-api-js";

export const FCK_METHOD_NAMES = Object.freeze(["anchor_artifact"]);
export const FCK_ALLOWANCE_YOCTO = nearToYocto("0.25");

export function resolveRegistryId(explicit) {
  const registryId = explicit ?? process.env.SKJOLD_REGISTRY_ID ?? "";
  if (!registryId) {
    throw new Error("SKJOLD_REGISTRY_ID is required for delegation key helpers");
  }
  return registryId;
}

export function resolveRpcUrl(explicit) {
  if (explicit) return explicit;
  if (process.env.NEAR_RPC_URL) return process.env.NEAR_RPC_URL;
  const network = (process.env.NEAR_NETWORK ?? "testnet").toLowerCase();
  return network === "mainnet"
    ? "https://rpc.mainnet.near.org"
    : "https://rpc.testnet.near.org";
}

export function createProvider(rpcUrl) {
  return new JsonRpcProvider({ url: resolveRpcUrl(rpcUrl) });
}

export function agentAccount(accountId, secretKey, provider = createProvider()) {
  if (!accountId) throw new Error("agentAccount requires an account id");
  if (!secretKey) throw new Error("agentAccount requires a secret key");
  return new Account(accountId, provider, KeyPairSigner.fromSecretKey(secretKey));
}

/** Add the delegation's function-call key to the agent account. */
export async function addFunctionCallAccessKey(
  account,
  publicKey,
  {
    contractId,
    methodNames = FCK_METHOD_NAMES,
    allowance = FCK_ALLOWANCE_YOCTO,
  } = {},
) {
  if (!account) throw new Error("addFunctionCallAccessKey requires an account");
  return account.signAndSendTransaction({
    receiverId: account.accountId,
    actions: [
      actions.addFunctionCallAccessKey(
        publicKey,
        resolveRegistryId(contractId),
        [...methodNames],
        allowance,
      ),
    ],
    waitUntil: "FINAL",
  });
}

/** Delete the delegation's function-call key (hygiene after revocation). */
export async function deleteKey(account, publicKey) {
  if (!account) throw new Error("deleteKey requires an account");
  if (!publicKey) throw new Error("deleteKey requires a public key");
  return account.signAndSendTransaction({
    receiverId: account.accountId,
    actions: [actions.deleteKey(publicKey)],
    waitUntil: "FINAL",
  });
}
