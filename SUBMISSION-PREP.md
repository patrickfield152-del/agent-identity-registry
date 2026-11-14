# SUBMISSION-PREP — skjold (LOCAL DRAFT, NOT SUBMITTED)

Tracks: `security`, `agents`. Deadline 2026-11-14T23:59:00Z.
No push, no remote, no tags, no X post, no submit. Local commit only.

## Judge quickstart (do X → see Y), MEASURED on Celesto Box A

```
.venv/bin/pytest -q                           -> 225 passed, 1 skipped, 0 warnings
cargo test --lib --test test_units            -> 15 passed, 0 failed
cargo near check                              -> Contract checked successfully, EXIT 0
cargo check --target wasm32-unknown-unknown   -> Finished dev profile, EXIT 0
pnpm install --frozen-lockfile                -> EXIT 0
pnpm dedupe --check                           -> EXIT 0, 0 duplicates
pip install --dry-run -e '.[api,test]'        -> EXIT 0 (mcp 2.3.0, fastapi 0.162.7)
import attestix.main                          -> "skjold MCP server loaded: 47 tools registered"
git diff --check                              -> EXIT 0
```

Host `cargo check` (native target) is the wrong gate. It prints `compile_error "Use cargo near build"`. Use `cargo near check` or the wasm target above.

## Recordable demo outline (human records, human posts)

1. Show one agent identity: register `agent1.registry.skjold.testnet`. Show the single FullAccess key and the `did:near` document.
2. Show a scoped function-call access key that authorizes one contract method.
3. Revoke the key and show the next call fail. One moment, visible result.

No screenshots-only demo. Q-012 requires a video when judges cannot open it. The post must tag @NEARProtocol and #NEARHackathon. Main writes no post.

## Payload fields — ALL EMPTY, human supplies every value

| Field | Rule | Value |
|---|---|---|
| requestId | UUID, generate ONCE (`node -e 'console.log(crypto.randomUUID())'`), reuse on 400/503 | EMPTY |
| projectName | 2-80 chars | EMPTY |
| leadName | 2-80 chars | EMPTY |
| email | valid, <=160, max 2 submissions per address (Q-015) | EMPTY |
| size | exactly one of `1`, `2 - 4`, `4 - 6`, `6 - 8`, `8+` | EMPTY |
| tracks | >=1 of defi/thesis/privacy/business/swarms/security/agents/realworld/games/nfts/memecoins/social/open, each once | EMPTY |
| nearAddress | 2-64 lowercase `^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$`, mainnet account the team creates | EMPTY |
| projectUrl | http(s), <=300, public repo, unique | EMPTY |
| demoUrl | http(s), <=300, published X post | EMPTY |
| idea | 20-2000 chars: problem, product, how NEAR fits | EMPTY |
| consent | `true` only after the human hears the notice verbatim | EMPTY |

Never add `website` (spam trap). Print the full JSON and wait for an explicit human yes. Code 201 means saved. Code 400 means fix `fields` with the same requestId. Code 403 means stop, with no retry. Code 409 means stop and ask the human. Code 413 means shorten the idea. Code 503 means wait with the same requestId.

## Rules checklist

- Q-003 requires a dedicated branch or `pre-hackathon` and `hackathon-submission` tags plus a README diff link. Local tags `pre-hackathon` and `hackathon-submission` exist (not pushed). 5 pre-existing wave tags (`wave-1` … `wave-4`) also exist and were not created for the submission.
- Q-012 permits a local-only demo with a public repo, a reproducible README, and a video post.
- Q-014 `LICENSE` present. Q-017 README Quickstart at line 5 with numbered steps.
- Q-015 requires naming any second project that shares this email in README. Disclosed: README names **stele** as the second project on this email. The shared email itself is the human's choice (max 2 submissions per address).
- Origin and baseline disclosure appears in README "Origin & baseline".

## Blockers (do not block submission)

`cargo clippy --target wasm32-unknown-unknown -- -D warnings` holds 8 `too_many_arguments` diagnostics on 4 public `#[near]` ABI methods. The signatures stay to preserve the on-chain ABI. All other Celesto Box A gates pass with 0 suppressions added.

## Attestation

Nothing published, pushed, tagged, or submitted. No payload value invented. The pytest line above was captured on Celesto Box A at tag `hackathon-submission` (`a8739da`); 3 docs-only commits on top have not been re-run there.
