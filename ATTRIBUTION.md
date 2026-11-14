# Attribution

## Origin project

skjold is a port of **attestix**, the open-source AI agent identity and signed-evidence
toolkit.

| Field | Value |
|---|---|
| Project | attestix |
| Owner | VIBETENSOR PRIVATE LIMITED |
| Source | https://github.com/VibeTensor/attestix |
| Baseline version | 0.5.0 |
| Baseline commit | `dcf823e` (`main`, 2026-10-30) |
| License | Apache License 2.0, see `LICENSE` |

### Reused from the origin

- The Python MCP / FastAPI / CLI service surface and the `Repository` / `Signer` seams.
- The Ed25519 canonical-JSON credential profile in `auth/crypto.py` and the UCAN
  delegation evidence and verification logic.
- The conformance vectors in `spec/verify/v1/`, unchanged.
- The origin's Python dependency set as declared in `pyproject.toml`.

### Added or replaced in this repository

- `README.md` rewritten for the NEAR port.
- `contracts/registry/` new Rust registry contract.
- `sdk/` new Node ESM package declaration.
- `.env.example`, `scripts/check-contract.sh`, `NOTICE` and this file.
- The origin's EAS / Base anchoring path is not used by the NEAR backend; the origin
  files are retained until the port replaces them.

## Third-party components

These are installed from their registries; none is vendored here.

| Component | Version | Used by | License |
|---|---|---|---|
| near-sdk | 5.30.2 | registry contract | MIT OR Apache-2.0 |
| near-sandbox | 0.4.1 | contract dev-dependencies | MIT OR Apache-2.0 |
| near-api (Rust) | 0.8.7 | contract dev-dependencies | MIT OR Apache-2.0 |
| cargo-near-build | 0.11.5 | contract dev-dependencies | MIT OR Apache-2.0 |
| near-api-js | 7.5.3 | sdk runtime dependency | MIT AND Apache-2.0 |
| mcp[cli], cryptography, PyJWT, filelock, fastapi, uvicorn, httpx, anyio | see `pyproject.toml` | Python package | as declared in the origin metadata |
