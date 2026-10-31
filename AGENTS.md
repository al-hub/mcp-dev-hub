# Common instructions for all AI contributors

Read this file, SECURITY.md, docs/ARCHITECTURE.md, docs/ROADMAP.md and docs/STATUS.md before editing.

## Public repository: mandatory privacy rules

- All tracked content, issues, PRs, commit messages, CI output and artifacts are public.
- Never copy personal context, conversation transcripts, real device identifiers, hostnames, IP addresses, account names, absolute home/workspace paths, SSH configuration, keys, tokens, runtime databases or logs into public surfaces.
- Use synthetic examples only: reserved `.invalid` domains, generic target aliases and `<...>` placeholders. Do not inspect local credential files for examples.
- Real configuration and job state belong outside the checkout. Never add them with `git add -f`.
- Run `npm run check` after staging only intended source files. Review staged diff manually; automated scanning is incomplete.
- Never print a detected secret in a test failure or diagnostic. Report only the file and category.
- If exposure is suspected, stop publishing affected material; revoke/rotate credentials and coordinate history cleanup. Deleting the current file alone is insufficient.

## Development workflow

- Inspect the actual branch/files; do not infer completion from plans or queued tool calls.
- Implement the next unfinished roadmap milestone; keep changes small and tested.
- Use feature branches and PRs after initial bootstrap. Do not overwrite concurrent changes.
- Use one Git worktree per concurrent writer. Never let two agents write the same checkout.
- Do not spawn agents unless the user explicitly authorizes delegation for the current work.
- Mark tests as passed only after execution. Update docs/STATUS.md with verified results and limitations, using synthetic data only.
- All tools must carry explicit target and workspace identifiers. Never fall back to local execution after an SSH failure.
- No shell execution until configured target/workspace authorization is validated. Path allowlists are not a sandbox for arbitrary commands; use a dedicated OS account/container when isolation is required.
- Keep MCP stdout protocol-only; logs go to stderr with redaction. Authentication, SSH host-key verification and private state storage are mandatory before remote execution.
- Do not auto-replay interrupted commands after restart. Use idempotency keys and explicit interrupted/unknown states.

## Observable development commands (tmux-first)

- For interactive or long-running development commands on an authorized WSL/Linux target (AI CLI, tests, builds, lint, debugging), use a named **project-specific tmux session/window by default**. The session must exist before launching the command; merely creating an idle session does not satisfy observability.
- Show a sanitized command summary, project/workspace identifier, execution ID, start/end status and exit code in the observed session. Capture only redacted, access-controlled output outside the public repository. Never print credentials, full sensitive arguments, environment dumps or private runtime paths for observability.
- Keep execution independent of observer attachment. Verify that a read-only observer can attach, detach and reattach without interrupting work; use read-only attachment where supported. tmux access is itself privileged and must be limited to authorized OS users.
- **Exceptions:** GitHub API operations, hosted CI, initial tmux installation/bootstrap/recovery, and commands on targets without validated tmux support may run outside tmux. Record the exception reason, execution outcome and an appropriate sanitized activity/evidence reference; do not misrepresent these operations as visible in tmux.
- Do not bypass target/workspace authorization, SSH host-key checks, process isolation or security controls to satisfy tmux-first operation. On tmux failure, report BLOCKED or use an explicitly authorized, observable fallback; never silently execute an unobserved command.
- This is a development workflow policy, not permission to implement or invoke the future MCP/SSH execution engine before issue #10 passes its acceptance gate. A written policy alone is not technical enforcement; issue #10 must test the actual runner and observer path.
