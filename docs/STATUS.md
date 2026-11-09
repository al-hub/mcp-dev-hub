# Handoff status

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

## 2026-11-10 — project-wide Option C security baseline (documentation only)

- An owner-approved design choice for #35 and future protected/root-owned updates is now recorded as a shared project default rather than only on a blocked feature PR: WSL-local three-principal independent Ed25519 trust boundary, one owner-local bounded bootstrap, no per-update sudo and no requirement for additional mobile/PC external signing apps.
- All future changes MUST keep real independent exact-HEAD Codex execution, strict CI/branch protection, two protected OS issuer identities and an immutable root-owned two-file updater, with authenticated signatures and atomic CAS/UNKNOWN/rollback semantics. Real PC/Galaxy/private-SSE and service/data acceptance remains required after install.
- This is a **design policy**, not a retroactive removal of the current #35 runtime's external device/GitHub App gates. Until an independently audited complete runtime replacement is installed, existing checks remain fail-closed and #35 is operating NO-GO.
- Scoped only to `AGENTS.md`, `README.md`, `SECURITY.md`, `docs/ARCHITECTURE.md`, `docs/ops/current-constraints.md`, this history entry and `docs/ops/protected-update-baseline.md`. No source code, root trust, signer key, service, GitHub approval or branch-protection modification.
- Real main-baseline tests: `node --test` **161/161 PASS** and `node scripts/check-privacy.mjs` **110 files PASS** with staged changes; `git diff --cached --check` PASS. Status remains document-only pending PR CI and normal merge.
