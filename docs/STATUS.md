# Handoff status

## 2026-11-07 #35 one-shot bootstrap source pack, synthetic restore and no-go guard

- Existing Draft PR #39 reused; no privileged install, service restart, secret transfer or OS trust change. The authenticated mobile→Termux→strict-SSH→WSL path was usable; existing Worker-14 and Dashboard user services were active. Original installed controller/policy remain root:root mode 0555.
- Added a reproducible, nonprivileged Git-blob source pack `scripts/protected-update-bootstrap-pack.mjs` with exact clean HEAD, explicit source allowlist, owner-private staging, manifest SHA-256 and fail-closed nofollow/size/identity checks. The pack deliberately sets `installAuthorized:false`, includes no live signer keys/token and is **not an installation authorization**.
- Actual independent Codex security review found **P2**: a FIFO or oversized fake `MANIFEST.json` could hang/exhaust the package verifier. Fixed using O_NOFOLLOW|O_NONBLOCK, bounded fstat and regular-file checks before reading, plus synthetic FIFO/oversized regression tests.
- Implemented an **uninstalled** original-file migration/restore candidate: exact baseline hashes, backup before single-pointer switch and digest-checked wrapper replacement; refuse unsafe root permissions, symlinked originals, altered backup, crash leftovers and nonmatching rollback. Added fixed no-argument root entrypoint candidate, explicitly refuses the current source-only bundle and running from any mutable checkout.
- Three separate **synthetic** package→baseline→wrapper→original-restore integration runs and three deterministic source bundle builds are covered by tests, not live protected OS updates. All original bytes are compared after restore. Earlier actual WSL Node suite at code HEAD `c5277e0de8ecbc7d0fcd6f096ba1d5a56b265789` **280/280 PASS**, privacy check PASS. Full final-HEAD CI, complete independent privileged security audit and physical root tests are separately required.
- The real immutable root updater, reviewer/approval independent issuer operation and local protected signing keys, baseline pinning, least-privilege one-shot installation policy/undo and 2/2 physical protected updates remain incomplete. **One-time admin installation remains NO-GO; #35 OPEN.** Keep global `AI_WRITE=0` / `AI_PUSH=0`, main protection and existing data unchanged.

## 2026-11-07 #35 verified continuation — immutable roots and historical operation-ID recovery (NOT DEPLOYED)

- Reused existing Draft PR #39 and one isolated clean WSL worktree, with recovered authenticated ClosePaw/Termux/strict-SSH access. Current Worker and Dashboard user services both reported **active**. No root, service, credential, private-data, branch-protection or global `AI_WRITE=0` / `AI_PUSH=0` change.
- Added a candidate **real-root path-ancestry guard** checking fixed release and private journal directory chains for root ownership, directory type, no symlinks, and no group/other write. Wired it into authenticated read-only root preflight before credentials/OS release inspection. Synthetic negatives verify unsafe ancestors and journal modes; it is **not** an installed root entrypoint.
- Upgraded the **uninstalled** journal candidate to **v2** to persist trusted `previousCommit` with new `head`, rejecting v1 records rather than guessing. Removed external recovery calls' authority to supply the previous version identity.
- Actual independent Codex read-only security review on an intermediate source HEAD found **P2 historical result loss**: querying verified A→B after B→C, or earlier rollback after later success, was incorrectly refused. Fixed by a bounded, owner/mode-checked read-only journal history; enforces monotonic non-overlapping timestamps, linked previous/new commit+hashes, terminal predecessors and no active/stale history lock. Reconciliation distinguishes superseded completed records from uncertain successors; all outcomes remain `safeToReplay:false`.
- Regression cases cover serial A→B→C, rollback followed by retry, successor in unknown state, unjournaled pointer changes, broken hash ancestry, clock regression and stale locks. Actual Linux WSL Node suite **256/256 PASS**, privacy scanner PASS. Exact code-head [strict CI #42328998039](https://github.com/al-hub/mcp-dev-hub/actions/runs/42328998039) completed **SUCCESS**: `bootstrap` `npm run check`, **256 PASS, 0 FAIL**, privacy scan (139 files) PASS.
- Fresh **real independent Codex** review on code HEAD `9641f01768afa000029ef5c6819365f431281e3f` and exact main BASE `175ba1a481d9a55c0567402a2c905f457c7601e5`: **no actionable defects found within the expressly non-deployed candidate scope**. Reviewer ran 8 permitted read-only test files; actual WSL/CI separately ran all 256. This is **not** root privileged implementation security approval or formal GitHub APPROVED.
- Real read-only OS inventory: the proposed root-managed `versions`, `current`, independent trust config and durable root journal directories remain **absent**. Existing Worker/Dashboard remain active. Physical protected revisions **0/2**.
- **NO-GO for administrator installation:** still missing fully implemented immutable privileged updater, distinct operational independent reviewer/approval issuer signing keys and pinned root policy, one-shot original-file backup/installer/undo, full privileged security audit and physical acceptance. Keep PR #39 **Draft/OPEN**, Issue #35 OPEN, #36/#37 dependencies OPEN. No sudo request or overbroad policy.

## 2026-11-07 #35 read-only restart reconciliation (NOT DEPLOYED)

- Reused existing Draft PR #39; added `src/ops/protected-update-reconcile.mjs` and 9 synthetic tests. A root-owned supervisor may later use this **information-only** candidate to compare a durable operation-ID record with the active two-file release. An absent, pending, interrupted, unknown or inconsistent operation never authorizes replay, health promotion, switch or rollback. No privileged entrypoint was added.
- Source HEAD `9c2b20d9bafb1664d8366eb2f4c4c9118dbd2694` exact [CI #42320436322](https://github.com/al-hub/mcp-dev-hub/actions/runs/42320436322): completed **SUCCESS**, `bootstrap` job `npm run check` SUCCESS. New negative tests cover absent operation, prepared, switch-pending, switched-but-not-verified, durable verified/rollback, unknown, false terminal pointer and incorrect identity.
- Android ClosePaw v0.1.108 is responding, but the target private-network probe reported **target_unreachable**, Android VPN not present; actual strict-host-key SSH to WSL timed out (confirmed failure, not unknown write). No command replay, root change, service change or data operation occurred. Real operating acceptance and new live Codex review are **NOT VERIFIED** in this checkpoint.
- The immutable root updater, independent reviewer/approval signing principals and their protected provisioning, one-time migration/backup/installer, full privileged-code audit, two physical protected revisions, formal protected merge/main CI and #36/#37 real unattended E2Es remain missing. **Do not request administrator authorization or close #35** based on this source-only improvement. Maintain `AI_WRITE=0`, `AI_PUSH=0` and current services and policies.

## 2026-11-07 #35 protected-update candidate continuation (NOT DEPLOYED)

- Reused existing Draft PR #39 and the exact fixed two-file protected-update scope. No administrator rights, new trust policy, root installation, service restart, data reset, branch-protection change, or global AI_WRITE/AI_PUSH change.
- Added **read-only original installed pair capture** with exact legacy owner/mode/regular-file/nlink/size checks, no-follow and nonblocking access, inode consistency and SHA-256 evidence. This is **not** a deployed root backup, trust-issuer or updater.
- Actual independent read-only Codex review of prior candidate HEAD `cb63e95918e5f421143a2760e509572c7bd975e3` found a P2 release directory allowlist inconsistency. On the same PR branch, activation now rejects unexpected version entries before reusing/activating a release; regression tests cover refused staging/CAS and preserved current pointer.
- Source HEAD `2a6a93316d52673b2d9fbd1871c95c4b1759eae3`: authenticated WSL Node 24.15 run **222/222 PASS** and privacy scan **PASS** (manual staged-diff review still required). Exact-head strict GitHub [CI #42259651189](https://github.com/al-hub/mcp-dev-hub/actions/runs/42259651189) **SUCCESS**, `bootstrap` job `npm run check` SUCCESS.
- Fresh independent protected Codex CLI read-only review on this code HEAD and exact BASE `175ba1a481d9a55c0567402a2c905f457c7601e5`: **no actionable defects within the explicitly non-deployed candidate scope**. Reviewer ran 39 supported read-only tests; filesystem-mutating and child-process tests were constrained by its sandbox, separately covered by the real WSL/GitHub checks. This is not GitHub formal APPROVED or privileged installation acceptance.
- Operating read-only observation: legacy controller/policy root-owned, protected original version layout not migrated; Worker-14 and Dashboard both active. Existing main workspace was not changed; validation used a separate clean worktree.
- **NO-GO for the one-time admin action:** independent live review/approval signing principals and protected private-key provision, immutable root updater, original migration/rollback installer, minimum policy wiring and a separate full privileged-code independent audit remain missing. Physical updates **0/2**, broad Issue-development E2Es **0/3**. Keep PR #39 Draft and Issues #35/#36/#37 OPEN. Never infer root authority from candidate CI.

---
## 2026-11-06 #35 — One-time bootstrap readiness inventory (no deployment)

- Rechecked AGENTS.md, SECURITY.md, the current ops constraints, and Issues
  #35, #36 and #37. A single bounded administrator bootstrap is preferred
  to repeated sudo prompts, but it must not be spent on incomplete code.
- A new authenticated read-only mobile→Termux→SSH→WSL probe returned Linux /
  exit 0. Existing protected controller/policy/AGY/Codex components were
  present, with both Worker and Dashboard user services running. Protected
  root directory is root-owned and non-group/other-writable.
- Fixed-version `versions` migration and the proposed protected evidence trust
  directory were absent. A bounded system-local executable inventory did not
  find a preinstalled protected updater. This is *not* a complete OS permission
  audit; existing narrow launcher privilege must be checked before a new rule.
- Wrote the scope/admission/rollback decision and no-repeat-sudo acceptance
  gates in [docs/PROTECTED_UPDATE_ONE_SHOT_BOOTSTRAP.md](PROTECTED_UPDATE_ONE_SHOT_BOOTSTRAP.md).
  For new root policy, issuer keys or updater code, require a separate explicit
  authorization **before** starting a job, not a surprise mid-run prompt.
- [CI #42219429483](https://github.com/al-hub/mcp-dev-hub/actions/runs/42219429483)
  succeeded for the new document-only scope commit. The previous independent
  Codex review covers only the older uninstalled candidate code, not an
  installed, independently audited root updater.
- **Still NO-GO for administrator action:** separately trusted live issuers,
  complete immutable root updater, reviewed migration/backup/rollback installer
  and physical unattended updates 0/2 remain missing. Do not claim #35 complete
  or proceed to #36/#37 acceptance. No credentials or protected files changed.

## 2026-11-06 #35 — Root current-release and request preflight (candidate only)

- Added `inspectProtectedCurrentSnapshot` to derive the exact previous
  controller pair hashes from the protected current version, rejecting
  unexpected files, unsafe modes and no-follow violations. No previous hashes
  are trusted solely from Worker input.
- Added bounded canonical `parseProtectedUpdateRequest` with an exact
  non-executable allowlist. Worker-supplied root paths, commands, trust keys,
  credentials, privileges and policy updates are forbidden.
- Added `preflightRootProtectedUpdateRequest`: fixed root-side read-only
  composition of authenticated GitHub/review evidence, actual installed
  release metadata and verified source bytes. Returns only bounded status;
  deliberately has **no** privileged install/switch/retry entrypoint.
- The first synthetic CI detected an internal missing owner argument in one
  CAS pointer check; corrected before acceptance. Exact candidate
  [CI #42211771953](https://github.com/al-hub/mcp-dev-hub/actions/runs/42211771953)
  passed. Independent protected Codex read-only review on its exact SHA
  returned no actionable defects within candidate scope. Reviewer could
  not execute wrapper subprocess tests in its sandbox; CI covered them.
- No root bootstrap was attempted. Missing: separately trusted reviewer and
  approval signing issuers/private key protection, reviewed installed
  immutable root updater, narrow administrator bootstrap, physical 2/2
  unattended protected updates and rollback/unknown E2E, formal GitHub
  APPROVED, protected merge/main CI. #35/#36/#37 remain OPEN.
- Preserve old root-controlled files, operational services, private state,
  branch protection and globally `AI_WRITE=0`, `AI_PUSH=0`.


## 2026-11-06 #35 — Authenticated evidence candidate (2026-11-06)

- Existing Draft PR #39 reused. Candidate fixed HTTPS GitHub API reader now
  validates the exact PR HEAD/BASE, required workflow ID/path, successful
  required bootstrap job, strict branch protection, and associated CI run's
  exact tested HEAD and BASE.
- Added canonical short-lived independent Codex **signed** review evidence
  with a reviewer signing principal distinct from the updater approval
  principal. Root-side read-only preflight loads the two pinned public keys
  and GitHub credential exclusively from a fixed root-owned directory;
  it never accepts arbitrary Worker-supplied key paths or network URLs.
- Candidate controller/policy bytes are fetched only from two fixed GitHub
  content paths at the approved immutable commit and SHA-256/size verified.
- An independent Codex review found two defects: unrelated/stale-base CI
  acceptance and rollback-restage conflict. Both were fixed; new tests
  verify stale CI base refusal, exact immutable release reuse after rollback,
  and early block of damaged existing versions.
- [Strict CI #42209694816](https://github.com/al-hub/mcp-dev-hub/actions/runs/42209694816)
  completed SUCCESS for the revised source and tests. A **new final-HEAD
  independent Codex review** is required after the documentation update.
- **Not deployed:** No root-owned immutable verified updater entrypoint,
  independent private signer/review attestor or installed root trust
  configuration. Noninteractive sudo cannot be assumed. No actual
  privileged A→B→C revisions or reboot/disconnect recovery evidence.
- #35/#36/#37 remain OPEN. Keep `AI_WRITE=0`, `AI_PUSH=0` globally and
  branch protection, Worker/Dashboard and private data unchanged.


## 2026-11-06 #35 candidate protected release chain — CODE ONLY

- Existing Draft PR #39 reused; introduced signed approval + persistent journal
  integration, staged fixed two-file versions, one atomic CAS release pointer,
  compare-and-swap rollback, and a fixed controller wrapper candidate matching
  the legacy controller's direct-invocation guard.
- Exact code/tests CI: [run #42204022313](https://github.com/al-hub/mcp-dev-hub/actions/runs/42204022313)
  SUCCESS for synthetic two consecutive updates, rollback on confirmed
  negative health, and unknown-never-replay. Additional wrapper/docs candidate
  [run #42204648331](https://github.com/al-hub/mcp-dev-hub/actions/runs/42204648331)
  SUCCESS; code was not installed under root.
- Physical read-only noninteractive sudo check returned password required.
  No broad authority, protected files, root service, branch protections or
  live Worker/Dashboard were modified.
- **Critical pending trust gate**: the frozen proof used in candidate
  transaction tests is NOT an authenticated independent GitHub/CI/Codex
  attestation. A separately reviewed immutable root verifier and independent
  signer/key bootstrap are required before installing any privileged entrypoint.
  See docs/PROTECTED_UPDATE_BOOTSTRAP.md.
- Missing: final-HEAD independent Codex review of the new candidate, root
  authorization and install, two genuine unattended protected source updates,
  failure/disconnect physical acceptance, PR/main CI after protected merge,
  and #35 CLOSED. Dependent #36/#37 remain OPEN. AI_WRITE=0/AI_PUSH=0 globally.


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
