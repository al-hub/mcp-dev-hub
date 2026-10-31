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

Use official MCP specification and SDK documentation when implementing the transport. Compatibility is verified per client, not assumed.
