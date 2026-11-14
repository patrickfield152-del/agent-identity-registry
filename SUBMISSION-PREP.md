# SUBMISSION-PREP — skjold (LOCAL DRAFT, NOT SUBMITTED)

Track: `security` (spec `p0-security.md`). Deadline 2026-11-14T23:59:00Z.
No push, no remote, no tags, no X post, no submit. Local commit only.

## Judge quickstart (do X → see Y), MEASURED pre-Celesto-only

```
py -3.14 -m pytest -q                 -> 224 passed, 2 skipped, 0 fail (6.84s)
cargo check --target wasm32-unknown-unknown -> Finished dev profile, EXIT 0
                                              (rust 1.100.0, near-sdk 5.30.2)
pnpm install --frozen-lockfile       -> EXIT 0
pnpm dedupe --check                  -> EXIT 0, 0 duplicates
pip install --dry-run -e '.[api,test]' -> EXIT 0 (mcp 2.3.0, fastapi 0.162.7)
import attestix.main (isolated mcp 2.3.0) -> "skjold MCP server loaded: 47 tools registered"
git diff --check                     -> EXIT 0
```

Host `cargo check` (native target) is the WRONG gate; it prints
`compile_error "Use cargo near build"`. Use the wasm target above.

## Recordable demo outline (human records, human posts)

1. Show one agent identity: register `agent1.registry.skjold.testnet`, show the
   single FullAccess key and the `did:near` document.
2. Show a scoped function-call access key authorizing one contract method.
3. Revoke the key and show the next call fail. One moment, visible result.
No screenshots-only demo: Q-012 requires a video when judges cannot open it.
Post must tag @NEARProtocol and #NEARHackathon. Main writes no post.

## Payload fields — ALL EMPTY, human supplies every value

| Field | Rule | Value |
|---|---|---|
| requestId | UUID, generate ONCE (`node -e 'console.log(crypto.randomUUID())'`), reuse on 400/503 | EMPTY |
| projectName | 2-80 chars | EMPTY |
| leadName | 2-80 chars | EMPTY |
| email | valid, <=160, max 2 submissions per address (Q-015) | EMPTY |
| size | exactly one of `1`, `2 - 4`, `4 - 6`, `6 - 8`, `8+` | EMPTY |
| tracks | >=1 of defi/thesis/privacy/business/swarms/security/agents/realworld/games/nfts/memecoins/social/open, each once | EMPTY |
| nearAddress | 2-64 lowercase `^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$`; mainnet account the team creates | EMPTY |
| projectUrl | http(s), <=300, public repo, unique | EMPTY |
| demoUrl | http(s), <=300, published X post | EMPTY |
| idea | 20-2000 chars: problem, product, how NEAR fits | EMPTY |
| consent | `true` only after the human hears the notice verbatim | EMPTY |

Never add `website` (spam trap). Print the full JSON and wait for an explicit
human yes. 201 = saved; 400 = fix `fields`, same requestId; 403 = stop, no retry;
409 = stop, ask human; 413 = shorten idea; 503 = wait, same requestId.

## Rules checklist

- Q-003 no new repo required: dedicated branch OR `pre-hackathon` +
  `hackathon-submission` tags + README diff link. **Not satisfied**: 5 pre-existing
  tags, none of the required pair, no diff link. Local tags deliberately not created.
- Q-012 local-only demo OK with public repo, reproducible README, video post.
- Q-014 `LICENSE` present. Q-017 README Quickstart at line 5 with numbered steps.
- Q-015 if a second project shares this email, this README must name it. Unresolved.
- Origin/baseline disclosure: README "Origin & baseline" at line 187.

## Blockers (do not block submission)

Celesto `Trial credit is too low to start this sandbox` → clippy/fmt/
cargo-near-check BLOCKED-BY-CELESTO. Firecrawl daily credits BLOCKED.
Exa MCP 402 → direct REST used. BoxLite §6 MEASURED `yQKk4IO6C4xa`.

## Attestation

Nothing published, pushed, tagged, or submitted. No payload value invented.
