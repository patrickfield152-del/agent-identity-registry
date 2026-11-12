# NUMBERS

One reproducible measured claim, recorded from a local `near-sandbox` run. Every value below is
copied from captured command output; nothing is estimated.

## Claim

Anchoring one credential with `anchor_credential` (operator/issuer signs, the registry writes the
credential record) burns a measured amount of gas on a local `near-sandbox` node. The number is the
transaction's total gas burnt — the transaction outcome plus every receipt it produces — as reported
by the RPC and read from `TransactionResult::Full(r).total_gas_burnt` in
`contracts/registry/tests/test_basics.rs`. It is printed in TGas (gas units / 1e12) with three
decimals by the end-to-end registry flow. This is a cost measurement, not a contract gas-income
claim (PV ≥ 87 removes the 30% contract gas reward).

**Measured: `3.195 TGas`** (identical on two fresh sandbox runs).

## Reproduce

From the repository root on the Celesto box:

```bash
cd contracts/registry && cargo test --test test_basics registry_flow_end_to_end -- --nocapture 2>&1 | grep MEASURED_ANCHOR_CREDENTIAL_TGAS
```

The test starts its own `near-sandbox`, builds the contract with `cargo-near-build`, deploys it, and
drives the full identity → credential → delegation → reputation → revocation flow. The marker line
has the form:

```
MEASURED_ANCHOR_CREDENTIAL_TGAS=<value with 3 decimals>
```

## Environment

| Item | Value |
| --- | --- |
| Host | Celesto Cloud box `cmp_512755789ee1` (Linux x86_64) |
| Workspace | `~/work/skjold` (repo root; contract at `contracts/registry`) |
| Rust | `rustc 1.99.1 (58cf8f9c3 2026-10-13)` |
| Cargo | `cargo 1.99.1 (5f94df478 2026-08-27)` |
| Node | `v24.16.0`, `near-api-js 7.5.3` in `sdk/node_modules` |
| Sandbox | `near-sandbox 0.4.0` (`near_sandbox::Sandbox::start_sandbox`) |
| Build | `cargo-near-build 0.11.5` via `cargo-near 0.23.0`; target `wasm32-unknown-unknown` |
| Target | `wasm32-unknown-unknown` with the sandbox `neard` shipped by `near-sandbox 0.4.0` |

## Runs

Two fresh runs of the reproduce command were executed on `cmp_512755789ee1`; both returned the same
value.

| Run | Date (UTC) | Commit | Box | `MEASURED_ANCHOR_CREDENTIAL_TGAS` | Log |
| --- | --- | --- | --- | --- | --- |
| 1 | 2026-11-12 | W4 final `b48c837` | `cmp_512755789ee1` | `3.195` | `evidence/w4-gas.log` (`exit 0`) |
| 2 | 2026-11-12 | W4 final `b48c837` | `cmp_512755789ee1` | `3.195` | `evidence/w4-gas2.log` (`exit 0`) |
