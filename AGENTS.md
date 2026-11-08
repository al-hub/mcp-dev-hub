# Common instructions for all AI contributors

Read this file, SECURITY.md, docs/ARCHITECTURE.md, docs/ROADMAP.md and docs/STATUS.md before editing.
Before environment-dependent work, read [docs/ops/current-constraints.md](docs/ops/current-constraints.md) for project-wide goals, security boundaries and issue ownership. Read the linked issue/PR for current technical blockers, dated evidence and release criteria; recheck only changed or stale facts. Keep docs/STATUS.md for work history. Documented capabilities never grant permissions.

## Mandatory MCP / SSH route selection (all issues and future sessions)

Select the **shortest authorized route for each operation**, not one remote path for an entire task. Apply this policy before running tools, keep the actual target/workspace and exact commit identifiable, and re-use already verified evidence.

1. **GitHub connector / API**: use directly for repository files, Issues, PRs, reviews, commit identity, Actions/CI and recorded evidence. Do not enter WSL just to perform a GitHub-native operation.
2. **Microduck MCP (default development entry)**: use for source investigation, scoped code editing, ordinary development tests and authorized agent coordination when its actual tools, workspace and permissions support the task. Confirm the workspace; do not assume Microduck and WSL share files. Delegate to agents only with the user's explicit authorization for the current work.
3. **ClosePaw → SSH → WSL (host-specific entry)**: use only when real host access is necessary: privileged/protected installation, trust and signing boundaries, host/Worker/Dashboard services, WSL-specific diagnostics, operational recovery/rollback and real end-to-end acceptance. Reuse existing verified access; do not route routine coding or GitHub queries through this chain.
4. **WSL Worker (production execution authority)**: remains the actual protected-automation executor; Microduck is a development/control entry and cannot substitute for independent Codex evidence, a trusted GitHub App approval, or root trust controls.

**Handoff rules:** GitHub Issue/PR and exact commit SHA are the shared source of truth across distinct workspaces. Isolate concurrent writers; validate and commit changes before handing them to another environment. Never reuse a test, review or approval for a different HEAD. If a route is unavailable, continue independent authorized work using a matching route, without guessing that another host is equivalent or falling back from SSH to local execution. Avoid duplicate connectivity checks and redundant setup. Preserve branch protection, real independent review, least privilege, protected keys, AI_WRITE=0 and AI_PUSH=0; changes to root trust policy still require explicit authorization. Report the actual route used and verified outcome, not intended or queued execution.

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
