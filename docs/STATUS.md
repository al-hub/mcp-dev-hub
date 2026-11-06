# Handoff status

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
