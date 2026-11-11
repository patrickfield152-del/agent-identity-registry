# skjold

Agent identity and verifiable evidence on NEAR. skjold is a port of
[attestix](https://github.com/VibeTensor/attestix): it keeps the Python MCP / REST / CLI
surface, the Ed25519 canonical-JSON credential profile and the conformance vectors, and
replaces the local JSON storage plus EAS-on-Base anchoring with one NEAR Rust registry
contract.

## The primitive

Two NEAR-native pieces carry the design.

**`did:near` identity registry.** Each agent is a sub-account of the registry account,
for example `agent1.registry.skjold.testnet`. The DID document is resolved from the
account's FullAccess keys, and each agent sub-account holds exactly **one** FullAccess
key, so the document has exactly one `#owner` verification method. The contract stores
the agent record, the sha256 digest of the signed UAIT payload (UAIT minus its mutable
fields), and the revocation state. The registry flag is the authority: revoking an agent
stops its registry calls but does not take over the sub-account.

**Function-call access keys as delegation.** A delegation is a function-call key on the
agent account restricted to `contract_id = SKJOLD_REGISTRY_ID` and
`method_names = ["anchor_artifact"]`. The registry additionally records the UCAN `jti`
and indexes the key (`delegation_by_key[fck_pubkey] -> jti`), so a revoked or
expired delegation is rejected on the next call even if the key was never deleted.
Function-call allowances are gas-only budgets, so every cap that matters is enforced by
the contract rather than by the key.

Around those two pieces:

- **Credentials** are signed off-chain and only their digest is anchored. The digest is
  `skjold-vc-digest/v1`: Base64(SHA-256 of the canonical credential minus `proof` and
  `credentialStatus`). This is a project profile, not the stock did:near ProofType cid,
  which hashes the whole credential.
- **Reputation** is a decayed aggregate (`sum(w * decay)`, `sum(decay)`,
  `last_update_ns`) decayed forward on each update. A 64-entry recent window feeds only
  the category breakdown, never the authoritative score.
- **TEE bindings** record a verified report digest, the signature kind (provider enclave
  or gateway), the optional model, the image digest, the attestation nonce and a pointer
  to the previous report digest. A gateway signature cannot claim a model.
- **Artifact anchors** record a 32-byte digest, a typed artifact kind, an explicit
  subject, the anchoring account and the block height and timestamp. The runtime exposes
  no transaction hash to a contract, so the client captures it from the RPC response.

The methods that implement this behavior are not in this revision; see [Status](#status).

## Architecture

```
   Python surface (MCP tools, FastAPI, CLI)          Node SDK
            |  Repository + Signer seams              |  near-api-js 7.5.3
            v                                         v
   +-----------------------------------------------------------------+
   |  registry contract (near-sdk 5.30.1)                            |
   |  registry.skjold.testnet (dev) / registry.skjold.near (mainnet)  |
   +-----------------------------------------------------------------+
      identity      credentials     delegation     reputation / TEE / anchors
```

- The **registry contract** is the owner of identity, credential, delegation, reputation,
  TEE and anchor state. This revision defines that state and the NEP-297 event enum
  under the `skjold-registry` standard; the methods that write it are not present yet.
- The **Python package** keeps the origin's service layer. Its `Repository` and `Signer`
  seams are the integration points for NEAR storage and NEAR transaction signing; no
  NEAR adapter is wired in yet.
- The **SDK** package is declared for Node ESM glue on near-api-js 7.5.3: key
  management, `did:near` resolution and the zero-funds demo. The reference resolver
  `@kaytrust/did-near-resolver` is a devDependency for the differential test only,
  because it carries its own near-api-js 5.x tree.

## Repository layout

```
contracts/registry/        Rust registry contract
  Cargo.toml               package skjold-registry 0.1.0, near-sdk 5.30.1
  src/lib.rs               contract state + #[init] new(operator)
  src/types.rs             record, enum and event payload types
  src/events.rs            NEP-297 "skjold-registry" event enum
  tests/test_basics.rs     state round-trip test
sdk/                       Node ESM package
  package.json             name skjold-sdk; near-api-js 7.5.3
  .nvmrc                   Node 22.22.2
scripts/check-contract.sh  the W1 build check
attestix/                  forked Python package (MCP / REST / CLI / services)
api/ auth/ blockchain/     origin top-level Python modules, retained
storage/ services/ tools/  origin top-level Python modules, retained
spec/verify/v1/            unchanged conformance vectors
.env.example               registry and key environment variables
```

## Status

This revision is the repository and contract foundation only.

Implemented:

- `contracts/registry/Cargo.toml`: package `skjold-registry` 0.1.0, edition 2021,
  `cdylib` + `rlib`, `near-sdk = "5.30.1"`, plus the pinned sandbox dev-dependencies
  (`near-sandbox 0.4.0`, `near-api 0.8.7`, `cargo-near-build 0.11.5`).
- `contracts/registry/src/lib.rs`: the contract state (`operator`, `agents`, `creds`,
  `delegations`, `delegation_by_key`, `interactions`, `reputation`, `interaction_ids`,
  `tee`, `tee_nonces`, `anchors`), one distinct storage prefix per structure, and
  `#[init] pub fn new(operator: AccountId)`.
- `contracts/registry/src/types.rs`: `AgentRecord`, `CredentialAnchor`,
  `DelegationRecord`, `Interaction`, `ReputationAggregate`, `SignatureKind`,
  `TeeBinding`, `ArtifactType`, `AnchorRecord` and the nine event payload types.
- `contracts/registry/src/events.rs`: the `Event` enum with nine variants, each version
  `1.0.0`.
- `contracts/registry/tests/test_basics.rs`: constructs the state with `new`, borsh
  serializes it, deserializes it back and checks the round trip.
- `sdk/package.json` and `sdk/.nvmrc`, `.env.example` and `scripts/check-contract.sh`.

Not implemented in this revision:

- Contract methods. `new(operator)` is the only registry entry point; the macro-generated
  `contract_source_metadata` view aside, there is no `create_agent`,
  `anchor_credential`, `record_delegation`, `record_interaction`,
  `bind_tee_attestation`, `anchor_artifact`, revocation or view method.
- The Python NEAR adapters. `attestix/` is still the origin tree over its file-backed
  storage; no `NearRepository`, no NEAR-backed `Signer`.
- The SDK modules under `sdk/src/` and the demo loop.
- Sandbox-backed tests. The only test is the state round trip.

The contract has not been audited by a third party.

## Build prerequisites

| Requirement | Version |
|---|---|
| Rust | 1.95 or newer (near-sdk 5.30.1 MSRV) |
| Wasm target | `wasm32-unknown-unknown` |
| Node | 22.22.2 or newer (`sdk/package.json` engines) |
| pnpm | 10.4.1 or newer |
| Python | 3.11 or newer for the current tree; the TEE SDK port targets 3.12 |
| cargo-near | 0.23.0 for deployment builds |

```bash
rustup target add wasm32-unknown-unknown
```

## W1 build check

From the repository root:

```bash
bash scripts/check-contract.sh
```

The script changes into `contracts/registry` and runs exactly:

```bash
cargo check --target wasm32-unknown-unknown
```

The state test is a normal host-target integration test:

```bash
cd contracts/registry
cargo test --test test_basics
```

The deployable artifact, once the contract methods land, is produced with cargo-near
0.23.0 from `contracts/registry`:

```bash
cargo near build non-reproducible-wasm
```

## Origin & baseline

skjold is derived from **attestix 0.5.0**, the AI agent identity and signed-evidence
toolkit by VibeTensor, at baseline commit `dcf823e` on `main` (2026-10-30). attestix is
distributed under the Apache License 2.0; the `LICENSE` file is retained unchanged, and
`NOTICE` and `ATTRIBUTION.md` record the origin and the reused components.

Reused from the origin:

- The Python MCP / FastAPI / CLI service surface and its `Repository` / `Signer` seams.
- The Ed25519 canonical-JSON credential profile (`auth/crypto.py`) and the UCAN
  delegation evidence.
- The conformance vectors in `spec/verify/v1/`, unchanged.
- The origin's Python dependency set, including `mcp[cli]`, `cryptography`, `PyJWT`,
  `filelock`, `fastapi`, `uvicorn`, `httpx` and `anyio`.

New in the port: the Rust registry contract (`near-sdk 5.30.1`), the Node SDK package
declaration (`near-api-js 7.5.3`), and the NEAR environment template. The origin's
EAS / Base anchoring code is not part of the NEAR backend.

## License

Apache License 2.0. See `LICENSE`, `NOTICE` and `ATTRIBUTION.md`.
