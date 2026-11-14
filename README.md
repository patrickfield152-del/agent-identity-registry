# skjold
**Agent identity and KYA (Know Your Agent) on NEAR.** The primitive uses **function-call access keys + did:near registry**. It has one contract (`registry.skjold.testnet`), a Python MCP/REST/CLI surface, and a Node SDK.

Each agent is a sub-account such as `agent1.registry.skjold.testnet` holding one FullAccess key; `did:near:agent1.registry.skjold.testnet` resolves to one `#owner` verification method. The registry stores the agent record and the canonical UAIT digest plus credential anchors, delegation records, the reputation aggregate, TEE bindings, and artifact anchors. Credentials are signed off-chain; the registry anchors only the digest. A delegation is a function-call access key on the agent account with `contract_id = registry.skjold.testnet` and `method_names = ["anchor_artifact"]`, indexed to the UCAN `jti`; revocation stops future calls even if the key remains installed.

**Problem.** Autonomous agents need portable, revocable identity and delegated authority that any verifier can check on-chain. skjold provides it: a DID per agent, anchored credentials, scoped function-call-key delegations with on-chain revocation, and a decayed reputation score.

**Tracks:** `security`, `agents`. **License:** Apache License 2.0 (`LICENSE`, `NOTICE`, `ATTRIBUTION.md`).
**Baseline:** tag `pre-hackathon` (commit `28b5b21`, the imported attestix tree). Diff: `git diff pre-hackathon..hackathon-submission` (see [Baseline, diff and dependencies](#baseline-diff-and-dependencies)).

## Quickstart
### Prerequisites
| Requirement | Version / note |
|---|---|
| Rust | 1.100+ (contract `rust-version = 1.100`) with target `wasm32-unknown-unknown` |
| cargo-near | 0.23.0 for deployment builds; test harness uses `cargo-near-build 0.11.5` |
| Node / pnpm | 26.13.1+ (`sdk/package.json` engines) / 12.18.0+ |
| Python | 3.12+ (`pyproject.toml` `requires-python`) |
| near-sandbox | 0.4.1; sandbox tests need Linux x86_64 (a macOS ARM64 binary also ships) |

```bash
rustup target add wasm32-unknown-unknown
cargo install cargo-near --version 0.23.0
```

### 1. Install the Node dependencies
```bash
(cd sdk && pnpm install --prod)
```

### 2. Check the contract for the wasm target
```bash
bash scripts/check-contract.sh
```

### 3. Run the zero-funds sandbox dry run
```bash
(cd contracts/registry && cargo test --test test_demo -- --nocapture)
```
No funded account, faucet, or API key is needed: the test starts a local `near-sandbox`, builds and deploys the registry, and runs `node sdk/src/demo.js` against the sandbox RPC. The output holds one `DEMO_TRANSCRIPT=` line and this summary:

```text
test node_demo_zero_funds ... ok
test result: ok. 1 passed; 0 failed
```
- `steps` has 9 entries: config and canonical UAIT digest, `create_agent`/`on_agent_created`, VC issue with `skjold-vc-digest/v1` cid anchor, `record_delegation`, FCK install, FCK `anchor_artifact`, two interactions with reputation/credential/`did:near` checks, `revoke_delegation`, and the refused FCK call.
- `identity.callback_landed`, `credential.valid_on_chain`, `delegation.revoked`, and `refusal.rejected` are all `true`; `refusal.error` contains `delegation revoked`.
- `identity.storage_credit_yocto` is `47810000000000000000000` (47.81 mN remaining from 50 mN). `did_document.verification_method` is `did:near:<agent>#owner` with the agent FullAccess Ed25519 key.

`evidence/DEMO-TRANSCRIPT.json` holds the reference capture. Sandbox tests compile only on Linux (`#![cfg(target_os = "linux")]` in both `tests/test_basics.rs` and `tests/test_demo.rs`); on another host `cargo test` reports zero tests for those files. Use a Linux machine or Linux guest.

### 4. Offline smoke: digest a credential with the Node SDK (no chain, no keys)
```bash
echo '{"issuer":"did:near:vc-issuer.registry.sandbox","credentialSubject":{"id":"did:near:agent1.registry.skjold.testnet","name":"agent1"}}' | node sdk/scripts/recompute-vc-digest.mjs
```
Observed on Windows, node v26.13.0:
```text
{"digest":"Gd3XyeMIntCJYtk4xeqMXC6lw7x0HVEFNmE7T0ftVxs=","profile":"skjold-vc-digest/v1","canonical_bytes":133}
```
Exit 0. The digest is `Base64(SHA-256(canonical JSON minus proof/credentialStatus))`, profile `skjold-vc-digest/v1`; the same canonicalizer byte-matches vector `canon-001` in `spec/verify/v1/vectors.json` (273 canonical bytes; see `spec/verify/v1/CONFORMANCE.md`). For the full 9-step demo, use step 3.

### 5. Run against testnet or a local node
The demo does not deploy the registry or create the issuer account. Point it at a registry initialized with `new(operator)`; the issuer account must already exist with one FullAccess key. Run from the repository root, after `pnpm install --prod` in `sdk`:
```bash
export SKJOLD_REGISTRY_ID=registry.skjold.testnet
export SKJOLD_OPERATOR_ACCOUNT=registry.skjold.testnet
export SKJOLD_OPERATOR_KEY=ed25519:...   # replace with the operator secret key
export SKJOLD_VC_ISSUER_ACCOUNT=vc-issuer.registry.skjold.testnet
export SKJOLD_VC_ISSUER_KEY=ed25519:...  # replace with the issuer secret key
export NEAR_RPC_URL=https://rpc.testnet.near.org
node sdk/src/demo.js
```
`SKJOLD_OPERATOR_ACCOUNT` defaults to `SKJOLD_REGISTRY_ID`; `SKJOLD_VC_ISSUER_ACCOUNT` defaults to `vc-issuer.<SKJOLD_REGISTRY_ID>`. `NEAR_NETWORK` labels the run and defaults to `testnet`. Stdout prints one JSON summary with the 9 steps; the process exits 0 only when all checks pass. Use testnet faucet funds only.

## Measured cost
**`3.195 TGas` per `anchor_credential`**: total gas burnt across the transaction outcome and all receipts, identical on two fresh runs (`NUMBERS.md` holds the environment and both run logs). `contracts/registry/tests/test_basics.rs` reads `TransactionResult::Full(r).total_gas_burnt` across the full sandbox lifecycle and prints `MEASURED_ANCHOR_CREDENTIAL_TGAS=3.195`. Reproduce with:

```bash
(cd contracts/registry && cargo test --test test_basics registry_flow_end_to_end -- --nocapture 2>&1 | grep MEASURED_ANCHOR_CREDENTIAL_TGAS)
```

## Storage credit
`create_agent` funds 50 mN of prepaid anchor storage per agent in the registry `storage_credit` ledger. A function-call access key cannot attach a deposit (`InvalidAccessKeyError::DepositWithFunctionCall`), so a zero-deposit `anchor_artifact` call debits the agent credit.

| Call path | Attached deposit | Credit effect |
|---|---|---|
| `create_agent` | 17 mN (10 mN sub-account stake + 7 mN `CreateAccount`) + record storage + 50 mN credit + credit storage. Excess is refunded | `on_agent_created` funds 50 mN |
| `register_existing_agent` (repair) | agent-record storage + 50 mN credit + credit storage. Excess is refunded | funds 50 mN once. A repeat call is a no-op that refunds the deposit |
| `anchor_artifact` from a delegated FCK | 0 | debits the record storage cost |
| `anchor_artifact` from the agent FullAccess key with a deposit | the record storage cost. Excess is refunded | untouched |
| Replay of an identical anchor | any attached deposit is refunded | untouched |

If the credit is smaller than the record cost, the call fails with `insufficient storage credit` and leaves credit untouched. The 50 mN grant has no top-up method; an exhausted credit blocks zero-deposit FCK anchors while deposited FullAccess calls still work. The demo starts at 50 mN and leaves `47810000000000000000000` yocto (47.81 mN) after the first FCK anchor.

## Architecture and layout
The Python layer reads contract views over JSON-RPC and submits writes through `sdk/src/tx.mjs` (near-api-js 7.5.3). Signed VC and UAIT bodies stay in the local body store; the contract stores digests and records.

```text
contracts/registry/
  Cargo.toml                         skjold-registry 0.1.0, near-sdk 5.30.2
  src/{lib,types,identity,credentials,delegation,reputation,tee,anchor,events}.rs
  tests/{test_units,test_basics,test_demo}.rs
sdk/
  src/demo.js                        zero-funds 9-step demo
  src/canonical.mjs                  canonical JSON, UAIT/VC digests, wire helpers
  src/keys.js                        FCK method scope, allowance, add/delete
  src/tx.mjs                         signed transaction transport for Python
  src/did-near.mjs                   did:near resolver and CLI
spec/verify/v1/                      7 cross-language conformance vectors
main.py                              MCP server (47 tools)
api/                                 FastAPI routers
cli.py                               `skjold` CLI
storage/near_repository.py           hybrid chain + body Repository adapter
signing/near_signer.py               NEAR key/digest helpers and NodeTxSigner
services/                            identity, credential, delegation, reputation, DID, blockchain, compliance, provenance
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

State collections use unique prefixes (for example `agents`, `creds`, `delegations`, `interactions`, `anchors`, `storage_credit`). Revocation is monotonic for identities, credentials, and delegations. Delegation checks accept the agent FullAccess key or a live, unexpired, unrevoked FCK bound to that agent. Reputation is `sum(w * decay) / sum(decay)` with a 30-day half-life; weights are `success = 1.0`, `partial = 0.5`, `failure = 0.0`, `timeout = 0.2`, and the 64-entry window feeds only the category breakdown. TEE quotes are verified off-chain; the contract stores the report digest, signature kind, optional model/image digest, nonce, and previous digest, and a gateway signature cannot claim a model. `AnchorRecord` stores the type (`Identity`, `Credential`, `Declaration`, `AuditBatch`), subject, caller, block height, and timestamp; contracts cannot see the transaction hash, so the client reads it from RPC.

### Python surface and retained MCP tools
The MCP server keeps **47 tools across 9 modules**: Identity 8, Agent Cards 3, DID 3, Delegation 4, Reputation 3, Compliance 7, Credentials 8, Provenance 5, Blockchain 6.

- `create_did_web` is a deprecated stub returning a `did:near:<registry>` redirect and an error; it never produces a hosting URL.
- `create_did_key` generates an Ed25519 keypair, registers a `<prefix>.<registry>` sub-account via `create_agent` (requires `SKJOLD_REGISTRY_ID`), and returns a one-time secret key.
- `resolve_did` resolves `did:key` locally and `did:near` through `sdk/src/did-near.mjs`; other DID methods are unsupported.
- The six anchor tools (`anchor_identity`, `anchor_credential`, `anchor_audit_batch`, `verify_anchor`, `get_anchor_status`, `estimate_anchor_cost`) manage `AnchorRecord`s; re-anchors return the existing record and the client captures the transaction hash.

`NearRepository` maps `identities`, `credentials`, `delegations`, `reputation`, and `anchors` to the contract and keeps `compliance`, `provenance`, `audit`, `idempotency`, and signed bodies locally. Only tenant `default` is accepted; without `SKJOLD_OPERATOR_KEY`, writes raise instead of faking success. `NodeTxSigner` writes one JSON request to `sdk/src/tx.mjs` on stdin and reads one JSON response, so secrets never appear in command arguments.

## Limits and security notes
- **No third-party audit.** External firms have not audited the contract or adapters.
- **Revocation is a registry cut-off, not account seizure.** Revoking an identity blocks agent-only registry calls without seizing keys; deleting the delegation FCK is optional hygiene.
- **Issuer key invariant.** The issuer account must hold exactly one FullAccess key; a second one breaks `#owner` uniqueness.
- **FCK allowance is gas-only and immutable.** Re-issue the key to change the allowance; treat `revoke_delegation` as authoritative.
- **Credential cid is a project profile.** `skjold-vc-digest/v1` is Base64(SHA-256 of the canonical credential minus `proof` and `credentialStatus`), differing from the stock did:near ProofType cid.
- **Contract JSON wire is raw for digests.** Contract `Digest32` is a 32-element JSON array (`[u8; 32]`); the Node demo uses `toWireDigest`, while the Python adapter sends Base64 strings and remains unverified against a live registry.
- **No mainnet.** No mainnet deployment or real-funds flow; use testnet or a local sandbox only.
- **Meta-transactions are not supported for agent-only calls.** A relayed NEP-366 call fails the `signer_account_pk()` check by design.

This project provides identity and KYA infrastructure, not a spend firewall or payments engine.

## Origin & baseline
skjold is a port of **attestix 0.5.0** by VibeTensor (VIBETENSOR PRIVATE LIMITED), under the Apache License 2.0. It keeps the Python MCP/FastAPI/CLI surface and its `Repository`/`Signer` seams, the Ed25519 canonical-JSON credential profile, the UAIT digest rules, the UCAN delegation evidence and verification logic, and the `spec/verify/v1/` vectors. It replaces EAS/Base anchoring with registry state and NEP-297 events; setting `SKJOLD_REGISTRY_ID` switches the default adapter to hybrid chain and local-body storage.

Origin: https://github.com/VibeTensor/attestix

## Status
- `contracts/registry/tests/test_units.rs` covers state, authority guards, events, and views against a mocked chain context.
- `contracts/registry/tests/test_basics.rs` runs the Linux near-sandbox flow: identity, credential, delegation, reputation, revocation, storage credit, and the `3.195 TGas` marker.
- `contracts/registry/tests/test_demo.rs` runs `node sdk/src/demo.js` against near-sandbox and checks all 9 steps, callback, VC validity, credit debit, revocation refusal, and `#owner` resolution.
- No testnet or mainnet deployment and no third-party security audit. The Python live chain-write path is unverified against a deployed registry (wire mismatch, see Limits).

## Baseline, diff and dependencies

Baseline: tag `pre-hackathon` marks the imported tree at `28b5b21`. The upstream project is attestix.
Submission: tag `hackathon-submission` marks the submitted state. `git rev-parse --short hackathon-submission` prints it.
Diff: `git diff pre-hackathon..hackathon-submission`. After publishing, https://github.com/<owner>/<repo>/compare/pre-hackathon...hackathon-submission.
Libraries, templates and AI-generated code are listed in `ATTRIBUTION.md` and `NOTICE`.

## License
Apache License 2.0. See `LICENSE`, `NOTICE` and `ATTRIBUTION.md`.

Q-015 (second project on this email): **stele** (slot NFTs with tenancy, tracks `nfts`, `realworld`).
