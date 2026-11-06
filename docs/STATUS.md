# Handoff status

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
