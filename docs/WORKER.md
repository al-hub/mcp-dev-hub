# Issue #14 — bounded durable worker

This worker is a **single-process, single-approved-scope, fixed-command** task runner. It does not accept arbitrary shell commands or make independent development decisions. It is distinct from the ChatGPT session and from the future #10 dashboard.

## Setup (authorized WSL only)

Requires Node 24+, tmux, a private writable state directory, and a trusted checkout. Set `MCP_DEV_HUB_APPROVED_SCOPE` to an explicitly authorized `project:target:workspace` triple. Set `MCP_DEV_HUB_STATE_DIR` to a directory **outside the checkout**, mode 0700. Do not commit environment files or state databases.

From the authorized checkout:

```sh
node scripts/worker.mjs enqueue demo-one synthetic-one demo local workspace
node scripts/worker.mjs enqueue demo-two synthetic-two demo local workspace
node scripts/worker.mjs run
```

Only the fixed kinds `synthetic-one`, `synthetic-two`, and `repo-check` can run. The last one runs the repository's own tests. The scope environment variable must exactly match the queued job. Jobs have unique IDs and persist in a local SQLite file. To inspect results from another shell, run `node scripts/worker.mjs status`. Read-only tmux observation: `tmux attach -r -t mcp-dev-hub-14`. Detach normally; do not kill the session.

## Long-running supervision

Use an authorized **systemd user service** (not a privileged system service) to invoke `node scripts/worker.mjs run` in the trusted checkout with its private environment. Configure `Restart=on-failure`, `RestartSec=5`, and an explicit working directory. Verify systemd user service availability and user lingering policy before enabling it. Never enable lingering or expand service privileges without approval. Alternatively, run the worker in a dedicated detached tmux window and verify its liveness; this is weaker than systemd restart supervision.

On startup the worker reconciles each RUNNING job against the retained tmux pane and its exact END marker. If the pane vanished without evidence, the job becomes UNKNOWN and the queue stops; **no automatic replay**. If the process is still running, it is observed rather than relaunched. Any FAILED, BLOCKED, or UNKNOWN job stops progression pending explicit resolution. No retry loop is implemented.

## Boundaries and outstanding integration

This is a bounded task executor, not a general SSH/MCP engine. Job state is private; a read-only, authenticated event projection to the #10 dashboard is still to be integrated. Protect the local tmux socket and state directory with OS account isolation. Run acceptance tests for service restarts, tmux read-only observer reconnect, and crash/uncertain states before closing #14.
