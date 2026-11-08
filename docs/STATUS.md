# Handoff status

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
