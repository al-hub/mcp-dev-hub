# Architecture

AI client → MCP transport/authentication → authorization → job manager → executor (local / SSH) → target workspace.
Coding CLI adapters use the same job manager and executor boundary.

- The first host is WSL/Linux; native Windows and other environments require separate acceptance tests.
- Hosting location and execution target are independent. A later cloud deployment still needs a reachable authenticated execution path.
- MCP is the tool interface, not an autonomous scheduler. Durable development requires a CLI runner and private persistent job state.
- Every operation identifies a target and workspace. No implicit SSH-to-local fallback.
- SSH uses configured aliases, BatchMode and StrictHostKeyChecking; no credentials in tool parameters/results.
- Canonical path and symlink checks are required for file tools. A workspace allowlist does not isolate arbitrary subprocesses.
- Serialize writers per workspace or use separate worktrees. Cancellation must address the process group and remote lifecycle.
- Persist job ID/idempotency key before launch; after crashes reconcile actual execution and mark interrupted/unknown. Never replay automatically.
- Private runtime configuration lives outside the checkout, selected by MCP_DEV_HUB_CONFIG. Private state/log storage also stays outside the checkout.
- Remote transport must remain unavailable until authentication, TLS deployment and origin validation are tested.

## Protected update trust boundary (project default; NOT deployed)

For #35 and later privileged/root-owned updater work, the agreed **Option C**
target is: untrusted Developer Worker → isolated exact-HEAD Codex runner
(signed real review receipt) → separate OS-bound reviewer **and** approver
(three distinct Ed25519 signing identities in total) → immutable root-owned
allowlisted two-file updater. The root gate independently verifies GitHub CI,
live protection, package/source/baseline and signed authorization; it cannot
accept a Worker-supplied PASS, token, signing key or arbitrary command.

Only a narrowly scoped locally owner-authenticated first bootstrap may
provision the protected runtime; subsequently approved operations require
zero interactive sudo. Preserve atomic CAS, non-replay/UNKNOWN reconciliation,
actual rollback and device/private-SSE/PC/Galaxy acceptance. No separate
mobile/PC external signature hardware is required by default; existing
GitHub branch requirements and existing source-enforced approval checks
remain effective until a complete audited replacement is deployed.

**Current implementation:** design/source-contract only on #35 PR #39.
The old root bootstrap and runtime still enforce existing device and Bot
gates. This document is not installation or merge authorization.
See [protected update baseline](ops/protected-update-baseline.md).

Use official MCP specification and SDK documentation when implementing the transport. Compatibility is verified per client, not assumed.
