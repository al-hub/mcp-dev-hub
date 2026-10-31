# Issue #10 continuity bootstrap

This is a limited, non-autonomous tmux observation bootstrap, **not** the future job manager.

- Run `node scripts/continuity.mjs start` on an authorized WSL development target.
- Run `node scripts/continuity.mjs check` to launch the fixed `npm run check` in the named tmux session.
- Observe with `tmux attach -r -t mcp-dev-hub-10`; detach without killing the session.
- Run `node scripts/continuity.mjs status` to inspect the private checkpoint.
- If a run is unresolved after a restart, inspect evidence first and mark it unknown with `reconcile`. Never auto-replay.

The checkpoint stays in the current OS user's private state directory (or the explicitly configured external state directory), never in the repository. No secret command arguments are accepted. This bootstrap does not autonomously schedule next tasks, guarantee survival of OS restarts, or prove completion. A robust execution manager must capture exit state, reconcile process liveness and implement authenticated access before #10 is complete.
