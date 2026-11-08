# Handoff status

## 2026-11-08 #36 trusted policy expiry across network I/O (Draft PR #44)

- A caller-supplied `nowMs` can be stale, and the authenticated Issue GET can finish after a short-lived externally verified policy expires. The existing one-shot adapter now checks `Math.max(nowMs, Date.now())` before token access and AGAIN after the bounded HTTP GET, before constructing an immutable candidate. The opt-in polling preflight rejects already expired policy before a durable attempt claim.
- Existing source/test HEAD `a005f9d3c345d8e57c9d842d55a842c63846fcd7`. Microduck focused GitHub/poll regression **19/19 PASS**, including expired caller clock and mid-flight expiry, full Node tests exit 0, privacy candidate check **117 files PASS**, `git diff --check` PASS. Final documentation HEAD requires exact-head strict GitHub CI.
- Source-only negative hardening; no new trust issuer, read credential, live Issue GET, Worker dispatch, AGY/Codex execution, official reviewer App APPROVED, root deployment, PR merge or Issue Close. Keep Draft, #36 OPEN, AI_WRITE=0 / AI_PUSH=0, branch protection and Worker/Dashboard/private state unchanged.


## 2026-11-08 #36 stale polling claim reconciliation (Draft PR #44)

- Existing opt-in polling now checks the immutable SQLite candidate ledger before reporting a previously persisted `candidate_only` state. A revoked/blocked candidate reports `blocked`; a missing or otherwise unverified candidate reports `unknown`. No external GitHub GET, token access, agent dispatch or new write authority is introduced by reconciliation.
- Source/test checkpoint `633dd024dcfab58c1f3b0b2d320bf0cecc6cfecd`: Microduck exact-branch focused poll tests **6/6 PASS**, full Node suite exit 0, privacy candidate scanner **117 files PASS**, `git diff --check` PASS. Final documentation HEAD needs its own strict GitHub CI confirmation.
- Still source-only. No trusted production policy issuer/credential, live Worker intake, independent Codex security PASS, official App APPROVED, protected root installation, merge, main CI or Issue Close. Keep Draft/OPEN, AI_WRITE=0 / AI_PUSH=0 and branch protection unchanged.


## 2026-11-08 #36 preflight policy-before-GET fix (Draft PR #44)

- The separately exposed one-shot intake now rejects missing, invalid, expired or mismatched policies before token-provider access or external GitHub Issue GET. Independent policy verification is required before outbound I/O; downstream candidate validation remains in force.
- Regression tests confirm zero credential calls and zero GETs for eight negative policy/scope variants. Code/test HEAD 464ba429894d239e625523210038a4f0577031f6: strict CI #42460938090 SUCCESS (https://github.com/al-hub/mcp-dev-hub/actions/runs/42460938090). Microduck exact HEAD: 15/15 focused, 188/188 full tests, privacy 117 files, and git diff check PASS.
- No trusted production issuer/token, live Worker poll, AGY/Codex, App approval, root update, protected merge or Issue Close. AI_WRITE=0 / AI_PUSH=0 and branch protection remain unchanged. This STATUS-only commit must have its own final-HEAD CI.

## 2026-11-08 #36 opt-in Worker intake boundary (Draft PR #44, not deployed)

- Added a bounded, opt-in Worker-side Issue polling hook and `src/jobs/issue-intake-poll.mjs`. It requires independently supplied trusted per-Issue policy verification and read-only credentials. The default running Worker supplies neither; no live polling or code execution is enabled.
- The SQLite poll-attempt claim is stored as `unknown` **before** an external GitHub GET. A successful authenticated snapshot is handed to the existing non-executable candidate ledger; failed, 429 or interrupted attempts stay `unknown` across process/database restart. An existing attempt or changed policy cannot cause another GET.
- Synthetic focused candidate/adapter/ledger/poll tests: **26/26 PASS** including duplicate, 429, database reopen, policy conflict, missing trust and no-job assertions. All Node tests executed via `node --test --test-reporter=dot` **exit 0** and privacy candidate scan **117 files PASS**, with staged diff check PASS (the Microduck command allowlist does not expose `npm`). No real Issue intake, token/policy provisioning, AGY, independent Codex, App APPROVED, root protected install, merge or 3-run E2E is claimed.
- `AI_WRITE=0`, `AI_PUSH=0`, branch protection, Worker/Dashboard services, protected root files and existing operations remain unchanged. CI/latest HEAD must be checked after publication.


## 2026-11-08 #36 one-shot persisted live snapshot checkpoint (Draft PR #44)

- Added `recordLiveGitHubIssueCandidate`: a single read of an externally authenticated, policy-verified Issue snapshot followed by immutable SQLite candidate admission. It does not start polling, an AI/Worker job, GitHub mutation, root operation or external retry.
- New focused tests establish durable admission, exact duplicate readback, changed-policy conflict, preservation of terminal blocks, 429 single-call refusal and no request without an independent policy or ledger. Focused intake/ledger/adapter **21/21 PASS**, Microduck full Node suite **exit 0**, privacy candidate scanner **115 files PASS**, `git diff --check` PASS and clean worktree.
- Exact code/test HEAD `935de0425c6cc4de375176edfaf5ae935eb31536`: [strict CI #42454858098](https://github.com/al-hub/mcp-dev-hub/actions/runs/42454858098) **completed SUCCESS**. This STATUS-only commit requires its own latest-HEAD CI check.
- Not a production Worker poller: no live read credential, trusted policy issuer, isolated AGY/Codex, signer, GitHub App APPROVED, protected root updater, merge/main acceptance or Issue Close. `AI_WRITE=0`, `AI_PUSH=0` and existing protected services remain unchanged.


## 2026-11-08 #36 authenticated read-only Issue snapshot adapter (Draft PR #44)

- Added `src/jobs/issue-intake-github.mjs`: fixed-origin, HTTPS GitHub GET for exactly one numeric Issue ID, bounded JSON response (64 KiB), no redirects, no retries on 429/timeout and separate externally supplied read-token provider.
- API repository, exact Issue URL/number/ID, open state and non-PR identity must match; an independent trusted policy verifier and the latest Issue timestamp must pass before issuing a **non-executable** candidate. Issue prose never grants code/OS/GitHub authority.
- New synthetic tests `tests/issue-intake-github-36.test.mjs`: 6/6 PASS, including 429/no-retry, spoofing, stale snapshots, oversize data, API failure, invalid credentials and no policy. Existing 12/12 candidate/ledger tests remain; full Microduck Node suite exit 0, privacy scan passed (115 files), clean workspace.
- GitHub exact-source CI for commit `8705bcba5e4880cc5cd2b827933405b69999ba10`: [#42453945720](https://github.com/al-hub/mcp-dev-hub/actions/runs/42453945720) SUCCESS. This section is an additional documentation-only commit; its own final HEAD CI must be checked separately.
- **NOT LIVE:** No deployed read-token issuer, Worker scheduler/dispatch, trusted scoped policy issuance, isolated AGY/Codex, App approval, protected merge, main CI or Issue Close. #35 remains blocked; PR #44 stays Draft and #36 remains OPEN. Existing `AI_WRITE=0`, `AI_PUSH=0`, root files and services unchanged.


## 2026-11-08 #36 non-executable Issue intake foundation (Draft PR #44)

- Added explicit per-Issue trusted scope/snapshot validation; Issue text never creates an execution, push or root grant. Different safe Issue requests produce distinct immutable candidate identities.
- Added a durable SQLite candidate ledger initialized by the existing Worker. Exact duplicates are idempotent, changes to an already-recorded Issue/policy conflict without replacement, and blocked/unknown records never silently resume. No new executable task type is enabled.
- Focused 6/6 intake and 6/6 ledger tests PASS, including Worker database reopen with existing job and event preservation. Microduck full Node suite exit 0; privacy scanner PASS. GitHub CI evidence is tracked in Draft PR #44.
- This is source only: no real GitHub Issue polling, AGY changes, sandbox execution, Codex signed receipt, App approval, physical root updater, protected merge, main CI or Issue Close. #35 and #36 remain OPEN; #37 production E2E not accepted.
- Existing Worker/Dashboard, production data, branch protection and global AI_WRITE=0/AI_PUSH=0 remain unchanged.

## 2026-11-04 #10 reviewer-app preflight

- Added a separately invoked, bounded GitHub App connection preflight using the existing scoped App client. Checks expected App bot identity, exact PR HEAD, PR author/base/state. No APPROVE endpoint and no background automation are exposed.
- Uses only externally configured App identity, installation ID, protected key file reference and exact expected HEAD. Without these, preflight returns BLOCKED without reading a key. No credentials are committed.
- Initial real execution is BLOCKED: required App runtime configuration was not provisioned in this execution context. Successful synthetic client tests do not establish a real GitHub App JWT or installation token exchange.
- Independent authenticated full-PR Codex PASS, verified acceptance evidence, legitimate GitHub review, current-head CI, production acceptance and issue close remain pending. Preserve production configuration and branch protection.

The original Stage 0 snapshot below is historical and does not describe the current #10 implementation state.

---

## Implemented

- Public repository scaffold and provider-neutral AI contributor instructions.
- Disabled synthetic target configuration, runtime shape validation and target/workspace selection.
- Executor and durable job interfaces (contracts only).
- Privacy candidate scanner with regression tests and GitHub CI definition.

## Not implemented

MCP runtime/SDK, actual file or command tools, SSH, durable storage, authentication, tunnels, CLI adapters, installer and service startup.

## Next work

Stage 1: introduce a pinned official SDK and lockfile, implement stdio handshake and one harmless tool, then workspace-scoped file operations and controlled local execution with tests.
Keep all real configuration outside the repository. Read AGENTS.md first.

## Validation

Local Node.js 24 validation: 7 tests passed; privacy candidate check passed for all staged source files. Remote CI results must be checked separately after push. No real device or client acceptance is claimed.
