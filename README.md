# skjold

**Agent identity and KYA (Know Your Agent) on NEAR.** The primitive is **function-call access keys + did:near registry**: one registry contract (`registry.skjold.testnet`), a Python MCP/REST/CLI surface, and a Node SDK.

Each agent is a sub-account such as `agent1.registry.skjold.testnet` and holds exactly one FullAccess key, so `did:near:agent1.registry.skjold.testnet` resolves to exactly one `#owner` verification method. The registry stores the agent record and canonical UAIT digest, credential anchors, delegation records, the reputation aggregate, TEE bindings and artifact anchors. Credentials are signed off-chain and only their digest is anchored. A delegation is a function-call access key on the agent account restricted to `contract_id = registry.skjold.testnet` and `method_names = ["anchor_artifact"]`; the registry indexes that key to the UCAN `jti`, so revoking the delegation is a registry cut-off even if the key stays installed.

## Quickstart

### Prerequisites

| Requirement | Version / note |
|---|---|
| Rust | 1.95 or newer (contract `rust-version = 1.95`) |
| Rust target | `wasm32-unknown-unknown` |
| cargo-near | 0.23.0 for deployment builds; the test harness uses `cargo-near-build 0.11.5` |
| Node | 22.22.2 or newer (`sdk/package.json` engines) |
| pnpm | 10.4.1 or newer |
| Python | 3.12 or newer (`pyproject.toml` `requires-python`) |
| near-sandbox | 0.4.0; the checked-in sandbox tests are gated to Linux x86_64 (near-sandbox also ships a macOS ARM64 binary) |

```bash
rustup target add wasm32-unknown-unknown
cargo install cargo-near --version 0.23.0
```

### 1. Install the Node dependencies

```bash
(cd sdk && pnpm install --prod)
```

**See:** `sdk/node_modules/near-api-js` at 7.5.3; the dev-only `@kaytrust/did-near-resolver` is not installed in the production graph.

### 2. Check the contract for the wasm target

From the repository root:

```bash
bash scripts/check-contract.sh
```

**See:** the script changes into `contracts/registry` and runs `cargo check --target wasm32-unknown-unknown`; it exits 0 on success.

### 3. Run the zero-funds sandbox dry run

From the repository root:

```bash
(cd contracts/registry && cargo test --test test_demo -- --nocapture)
```

**See:** the test starts a local `near-sandbox`, creates `registry.sandbox`, `operator.sandbox` and `vc-issuer.registry.sandbox`, builds and deploys the registry, then runs `node sdk/src/demo.js` against the sandbox RPC with generated keys. The test output contains the `DEMO_TRANSCRIPT=` line and then:

```text
test node_demo_zero_funds ... ok
test result: ok. 1 passed; 0 failed
```

and prints one `DEMO_TRANSCRIPT=` JSON line. In that transcript:

- `steps` has 9 entries, in this order: config and canonical UAIT digest; `create_agent` plus the `on_agent_created` callback; issue a W3C VC and anchor its `skjold-vc-digest/v1` cid; `record_delegation`; install the FCK; anchor an artifact as the agent through the FCK; record two interactions and verify reputation, credential and `did:near`; `revoke_delegation`; the next FCK call refused by the registry plus `get_delegation(jti).revoked`.
- `identity.callback_landed` is `true`, `credential.valid_on_chain` is `true`, `delegation.revoked` is `true`, and `refusal.rejected` is `true`.
- `identity.storage_credit_yocto` is `47810000000000000000000`, i.e. 47.81 mN left of the 50 mN credit after the zero-deposit FCK anchor.
- `refusal.error` contains `delegation revoked`.
- `did_document.verification_method` is `did:near:<agent>#owner`, and `did_document.public_key_base58` is the agent's FullAccess Ed25519 key.

The same JSON is the demo's stdout; the reference capture is `evidence/DEMO-TRANSCRIPT.json` in this repository. The test exits non-zero if any of those assertions fail.

The sandbox tests are compiled only on Linux: both `tests/test_basics.rs` and `tests/test_demo.rs` begin with `#![cfg(target_os = "linux")]`. On another host `cargo test` reports zero tests for those files; use a Linux machine or Linux guest.

### 4. Run against testnet or a local node

The demo does not deploy the registry or create the issuer account. Point it at a registry that you have already deployed and initialized with `new(operator)`, and at an issuer account that already exists with exactly one FullAccess key.

From the repository root, after `pnpm install --prod` in `sdk`:

```bash
export SKJOLD_REGISTRY_ID=registry.skjold.testnet
export SKJOLD_OPERATOR_ACCOUNT=registry.skjold.testnet
export SKJOLD_OPERATOR_KEY=ed25519:...   # replace with the operator secret key
export SKJOLD_VC_ISSUER_ACCOUNT=vc-issuer.registry.skjold.testnet
export SKJOLD_VC_ISSUER_KEY=ed25519:...  # replace with the issuer secret key
export NEAR_RPC_URL=https://rpc.testnet.near.org
node sdk/src/demo.js
```

`SKJOLD_OPERATOR_ACCOUNT` defaults to `SKJOLD_REGISTRY_ID`; `SKJOLD_VC_ISSUER_ACCOUNT` defaults to `vc-issuer.<SKJOLD_REGISTRY_ID>`. For a local node, set `NEAR_RPC_URL` to that node's RPC endpoint; `NEAR_NETWORK` labels the run and defaults to `testnet`.

**See:** step logs on stderr and exactly one JSON summary on stdout with the same fields as the sandbox transcript, including the 9 steps, transaction hashes, on-chain credential validity, the reduced storage credit, the revocation and the refusal. The process exits 0 only when every step and check passes. The checked-in automated path is the sandbox run above; this testnet invocation is for a registry you deployed.

Use only testnet faucet funds. There is no real-funds flow and no mainnet deployment in this repository state; do not point the demo at mainnet.

## Measured cost

**`3.195 TGas` per `anchor_credential`**, measured as the transaction's total gas burnt: the transaction outcome plus every receipt it produces. The value is read from `TransactionResult::Full(r).total_gas_burnt` in `contracts/registry/tests/test_basics.rs` and printed in TGas with three decimals.

Two identical fresh sandbox runs on the Celesto box `cmp_512755789ee1` both returned `3.195`; the raw logs are `evidence/w4-gas.log` and `evidence/w4-gas2.log`, and the full environment/run ledger is `NUMBERS.md`.

Reproduce from the repository root:

```bash
(cd contracts/registry && cargo test --test test_basics registry_flow_end_to_end -- --nocapture 2>&1 | grep MEASURED_ANCHOR_CREDENTIAL_TGAS)
```

The marker line has the form `MEASURED_ANCHOR_CREDENTIAL_TGAS=3.195`. The test starts its own sandbox, builds and deploys the contract, and drives identity, credential, delegation, reputation and revocation.

This is a cost measurement, not gas income. NEAR protocol version 87 and later (PV≥87) removed the 30% contract gas reward, so the registry earns nothing from the gas burnt by `anchor_credential`.

## Storage credit

`create_agent` funds exactly **50 mN** of prepaid anchor storage per agent. The credit is held in the registry's `storage_credit` ledger, not on the agent account, and it is funded once per agent.

A function-call access key cannot attach a deposit on NEAR: nearcore rejects such a transaction with `InvalidAccessKeyError::DepositWithFunctionCall`. The registry therefore treats a zero-deposit `anchor_artifact` from a live delegated FCK as a debit against the agent's credit.

| Call path | Attached deposit | Credit effect |
|---|---|---|
| `create_agent` | at least 17 mN (10 mN forwarded to the sub-account plus the 7 mN `CreateAccount` charge) + agent-record storage + 50 mN credit + credit-entry storage; excess refunded | `on_agent_created` funds exactly 50 mN |
| `register_existing_agent` (repair) | agent-record storage + 50 mN credit + credit-entry storage; excess refunded | funds exactly 50 mN once; a repeat call is an idempotent no-op that refunds the whole deposit |
| `anchor_artifact` from a delegated FCK | 0 | debits the record's storage cost |
| `anchor_artifact` from the agent's FullAccess key with a deposit | the record's storage cost; excess refunded | untouched |
| Replay of an identical anchor | any attached deposit is refunded | untouched |

If the credit is smaller than the record cost, the call fails closed with `insufficient storage credit` and the credit is not debited. An exhausted credit blocks zero-deposit FCK anchors; the agent can still anchor through its FullAccess key with a deposit. There is no top-up entry point in this contract revision, so the 50 mN grant is finite.

The demo exercises the path: the credit starts at 50 mN, the first zero-deposit FCK anchor leaves `47810000000000000000000` yocto (47.81 mN), and the transcript records that value. The sandbox suite also asserts the debit, the no-double-charge replay, the untouched credit on a deposited FullAccess call, and the refusal when an oversized record exceeds the credit.

## Architecture and layout

```text
  Python MCP / REST / CLI          Node SDK
   Repository + Signer seams       demo, DID, tx transport
            |                              |
            v                              v
  NearRepository  ---- tx.mjs ---->  registry contract
            |                         (near-sdk 5.30.1)
            +--> local body store     NEP-297 events
```

The Python surface reads contract views over JSON-RPC and submits writes through `sdk/src/tx.mjs`; the Node SDK talks to the same contract with near-api-js 7.5.3. Signed VC/UAIT bodies never go on chain: the contract stores digests and records, while the Python adapter keeps bodies in the local body store.

```text
contracts/registry/
  Cargo.toml                         skjold-registry 0.1.0, near-sdk 5.30.1
  src/{lib,types,identity,credentials,delegation,reputation,tee,anchor,events}.rs
  tests/test_units.rs                host tests with a mocked chain context
  tests/test_basics.rs               Linux sandbox end-to-end flow + gas marker
  tests/test_demo.rs                 Linux sandbox + Node demo harness
sdk/
  src/demo.js                        zero-funds 9-step demo
  src/canonical.mjs                  canonical JSON, UAIT/VC digests, wire helpers
  src/keys.js                        FCK method scope, allowance, add/delete
  src/tx.mjs                         signed transaction transport for Python
  src/did-near.mjs                   did:near resolver and CLI
  scripts/recompute-vc-digest.mjs    digest recomputation
spec/verify/v1/                      7 cross-language conformance vectors
scripts/check-contract.sh            wasm32 type check
tests/                               Python unit and repository/signer contract tests
pyproject.toml                       Python package, `skjold` console script
```

The Python package keeps the retained service surface. Paths below are relative to its root:

```text
main.py                              MCP server (47 tools)
api/                                 FastAPI routers
cli.py                               `skjold` CLI
storage/near_repository.py           hybrid chain + body Repository adapter
signing/near_signer.py               NEAR key/digest helpers and NodeTxSigner
services/                            identity, credential, delegation, reputation,
                                     DID, blockchain, compliance, provenance
tools/                               MCP tool modules (47 tools across 9 modules)
```

### Contract modules and entry points

| Module | Responsibility | Entry points |
|---|---|---|
| `lib.rs` | state, initialization, storage accounting | `new(operator)` |
| `identity.rs` | agent sub-accounts and did:near binding | `create_agent`, `on_agent_created` (private callback), `register_existing_agent`, `revoke_identity`, `get_identity`, `list_identities` |
| `credentials.rs` | credential digest anchors | `anchor_credential`, `revoke_credential`, `is_credential_valid`, `get_credential_anchor`, `list_credentials` |
| `delegation.rs` | UCAN records and FCK enforcement | `record_delegation`, `revoke_delegation`, `get_delegation`, `list_delegations` |
| `reputation.rs` | decayed trust aggregates | `record_interaction`, `get_reputation`, `query_reputation` |
| `tee.rs` | verified TEE report bindings | `bind_tee_attestation`, `get_tee_attestation` |
| `anchor.rs` | typed artifact anchors and credit | `anchor_artifact`, `get_anchor`, `get_anchor_status`, `estimate_anchor_cost`, `get_storage_credit` |
| `events.rs` | NEP-297 events | 9 variants under the `skjold-registry` standard, version `1.0.0` |
| `types.rs` | records, enums, event payloads | `Digest32 = [u8; 32]` and the serialized record types |

Every state structure has its own storage prefix: `agents`, `creds`, `delegations`, `delegation_by_key`, `interactions`, `reputation`, `interaction_ids`, `tee`, `tee_nonces`, `anchors` and `storage_credit`. Revocation is monotonic for identities, credentials and delegations.

Delegation enforcement accepts the agent's own FullAccess key, or a signer key that is indexed to a delegation belonging to the same agent, not revoked and not expired. A NEP-366 meta-transaction puts the relayer's key in `signer_account_pk()`, so agent-only methods must never be relayed.

Reputation is `sum(w * decay) / sum(decay)` with a 30-day half-life. Outcome weights are `success = 1.0`, `partial = 0.5`, `failure = 0.0`, `timeout = 0.2`. The 64-entry recent window feeds only the category breakdown, not the authoritative score.

TEE quotes are verified off-chain; the contract records the verified report digest, signature kind, optional model and image digest, attestation nonce and previous report digest. A gateway signature cannot claim a model. Artifact anchors record a typed `AnchorRecord` (`Identity`, `Credential`, `Declaration` or `AuditBatch`), an explicit subject, the anchoring account, block height and timestamp. The runtime exposes no transaction hash to a contract, so the client captures it from the RPC response.

### Python surface and retained MCP tools

The MCP server keeps **47 tools across 9 modules**: Identity 8, Agent Cards 3, DID 3, Delegation 4, Reputation 3, Compliance 7, Credentials 8, Provenance 5, Blockchain 6.

Semantic changes in the port:

- `create_did_web` is a deprecated compatibility stub. It returns a `did:near:<registry>` redirect and an explanatory error, and never produces a hosting URL.
- `create_did_key` no longer creates an ephemeral `did:key`. It generates an Ed25519 keypair, derives a named `<prefix>.<registry>` sub-account, registers it through `create_agent`, and returns the secret key once. It requires `SKJOLD_REGISTRY_ID`.
- `resolve_did` resolves `did:key` locally and `did:near` from the account's FullAccess keys through `sdk/src/did-near.mjs`; other DID methods are unsupported.
- The six anchor tools (`anchor_identity`, `anchor_credential`, `anchor_audit_batch`, `verify_anchor`, `get_anchor_status`, `estimate_anchor_cost`) operate on typed `AnchorRecord`s. Idempotent re-anchors return the existing record; the transaction hash is captured client-side.

`NearRepository` maps the chain collections `identities`, `credentials`, `delegations`, `reputation` and `anchors` onto contract views and calls. Off-chain documents (`compliance`, `provenance`, `audit`, `idempotency`) and signed bodies stay in the local body store. The adapter accepts only the single tenant `default`; any other tenant raises an error. Without `SKJOLD_OPERATOR_KEY` the client is read-only and mutating paths raise instead of pretending a write landed.

`NodeTxSigner` sends one JSON request to `sdk/src/tx.mjs` on stdin and reads one JSON response; key material never appears on the process command line.

## Limits and security notes

- **No third-party audit.** The contract and adapters have not been audited by an external firm.
- **Single tenant.** `default` is the only accepted tenant in the Python adapter; there is no multi-tenant isolation in this demo.
- **Revocation is a registry cut-off, not account seizure.** Revoking an identity stops agent-only registry calls; it does not transfer or take over the agent's account or keys. Deleting the delegation FCK is optional hygiene.
- **Issuer key invariant.** The issuer account must hold exactly one FullAccess key, the VC signing key. The demo verifies the on-chain key list before signing. A second FullAccess key breaks the one-`#owner` did:near invariant.
- **FCK allowance is gas-only and immutable.** The function-call allowance budgets gas; it is not a token spend cap and cannot be edited in place. Re-issue the key to change it, and treat `revoke_delegation` as the authoritative cut-off.
- **Credential cid is a project profile.** `skjold-vc-digest/v1` is Base64(SHA-256 of the canonical credential minus `proof` and `credentialStatus`). It is not the stock did:near ProofType cid, which hashes the whole credential.
- **Storage credit is finite.** The 50 mN grant has no top-up method in this contract revision. An exhausted credit blocks zero-deposit FCK anchors; deposited FullAccess calls still work.
- **Contract JSON wire is raw for digests.** The contract's `Digest32` is a 32-element JSON number array (`[u8; 32]`). The Node demo sends that form via `toWireDigest`; the Python adapter sends Base64 digest strings, so its live chain-write path is a known wire risk and has not been exercised against a deployed registry.
- **Sandbox tests are Linux-only.** `tests/test_basics.rs` and `tests/test_demo.rs` are `#![cfg(target_os = "linux")]`; near-sandbox 0.4.0 ships Linux x86_64 and macOS ARM64 binaries, but the checked-in sandbox tests run on Linux only.
- **No mainnet.** There is no mainnet deployment in this repository state and no mainnet claim; use testnet or a local sandbox only.
- **Meta-transactions are not supported for agent-only calls.** A relayed NEP-366 call fails the `signer_account_pk()` check by design.

This is identity and KYA infrastructure, not a spend firewall or a payments policy engine.

## Origin & baseline

skjold is derived from **attestix 0.5.0**, the open-source AI agent identity and signed-evidence toolkit by **VibeTensor** (VIBETENSOR PRIVATE LIMITED), at baseline commit `dcf823e` on `main` (2026-10-30). attestix is distributed under the Apache License 2.0; `LICENSE` is retained unchanged, and `NOTICE` and `ATTRIBUTION.md` record the origin and the third-party components. The Python package keeps the `attestix` module path and the `skjold` distribution/console-script name.

Reused from attestix:

- The Python MCP / FastAPI / CLI service surface and its `Repository` / `Signer` seams.
- The Ed25519 canonical-JSON credential profile, the UAIT digest rules and the UCAN delegation evidence and verification logic.
- The conformance vectors in `spec/verify/v1/`, unchanged.
- The Python dependency set declared in `pyproject.toml`.

Replaced in the port: the origin's EAS / Base anchoring path is replaced by registry state and NEP-297 events, and its file-only storage default becomes the hybrid registry + local-body adapter when `SKJOLD_REGISTRY_ID` is set.

Origin: https://github.com/VibeTensor/attestix

## Status

Sandbox-verified from this repository state on Linux:

- `contracts/registry/tests/test_units.rs`: host-side tests with a mocked chain context (state round trip, authority guards, event envelope, view behavior).
- `contracts/registry/tests/test_basics.rs`: full identity → credential → delegation → reputation → revocation flow on near-sandbox, including storage-credit debit, replay, deposited FullAccess call, insufficient-credit refusal and repair. It prints the measured `3.195 TGas`.
- `contracts/registry/tests/test_demo.rs`: runs the real `node sdk/src/demo.js` against near-sandbox and asserts the 9 steps, the landed `create_agent` callback, on-chain VC validity, the credit debit, the revoked delegation and the registry refusal, and one `#owner` in the `did:near` document.

Not done or not claimed in this repository state:

- No testnet deployment is included or claimed. The testnet command requires a registry you deployed and initialized.
- No mainnet deployment.
- No third-party security audit.
- The Python adapter's live chain-write path is not verified against a deployed registry; the wire mismatch is listed under Limits.
- Submission and demo video are human actions, not repository outputs.
- No prize is claimed. This repository is not a winning hackathon entry, and the upstream project it ports was not a hackathon winner.
- This is identity and KYA only, not a spend firewall.

## License

Apache License 2.0. See `LICENSE`, `NOTICE` and `ATTRIBUTION.md`.
