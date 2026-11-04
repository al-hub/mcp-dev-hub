# PR completion automation contract (Issue #10)

Goal: one requested PR advances through review, findings remediation, CI, private staging, PC and Galaxy acceptance, and merge without repetitive prompts. A green CI run alone never completes this contract.

1. Identify the exact PR and pin its head SHA; check approved repository, scope and write permissions.
2. Run an independent reviewer, separate from the author, via durable Worker/tmux. Split review into bounded areas. Store each attempt, result and redacted evidence in SQLite.
3. When an attempt fails, first reconcile the existing process and output; do not replay uncertain or still-running work. For verified transient errors, automatically retry at most **three additional times** after 10, 30, and 90 seconds. For auth, access, policy, invalid-input and deterministic failures: BLOCKED with no retry. Preserve the counter across restarts and use transactional compare-and-swap claims to prevent parallel duplicate attempts.
4. CI failures have their own bounded recovery budget, separate from independent review retries. Classify each failed job before retrying: only confirmed transient infrastructure/network/rate-limit failures may trigger automatic re-runs of failed jobs, up to three additional attempts (10/30/90 seconds). Deterministic test or compilation failures require a code fix and a NEW commit SHA; never burn retries on the unchanged faulty SHA. Record the per-SHA CI retry count persistently and BLOCK after exhaustion. Do not run multiple CI retry controllers at once, or call a fresh push-triggered CI run an automatic retry. SQLite retry scheduler, exclusive claim, and GitHub failed-job rerun API dispatcher are implemented in modules with synthetic tests. Worker loop polling for pre-scheduled retries is now wired and has a synthetic test. Automatic CI failure classification and enqueueing, production Worker activation, and real GitHub rerun evidence remain NOT verified; do not imply full automation is live.
5. For deterministic test, compilation or lint errors, classify logs and dispatch a scoped AI CLI fix task (maximum three code-correction attempts per PR failure loop; separate from infrastructure retries). Every fix must produce a NEW commit SHA, run CI again and undergo independent review by a different agent. Never count an unchanged SHA as a fix or approve a patch using its author agent. Persist the remediation budget before running the live task. `src/jobs/ci-remediation.mjs` currently provides only fail-closed decision logic and tests; the actual AI fix dispatch, durable counter, and fresh-SHA monitoring are NOT integrated.
6. Stage privately with a service health check and a real authenticated SSE reconnect test. No public exposure or replacement of the production worker on CI success alone.
7. Verify PC and Galaxy access with real acceptance evidence. If direct device access or required approvals are unavailable, set BLOCKED and report the exact missing evidence; never invent a PASS.
8. Merge only when the required independent review, checks, security gates, device acceptance and permissions all pass on the same target SHA. Do not silently merge a moving head.
9. Provide a dashboard progress view and optional manual retry/resume control. Manual controls never reset the max-retry safety limit.

Current status: OpenCode retry and result-collection helpers have been added to the Worker, but live WSL review and end-to-end orchestration are unverified. CI retry dispatch helper is now called by the Worker source loop for pre-scheduled jobs. Live failure classification, live AI fix dispatch, production deployment, end-to-end orchestration, release gates and device acceptance remain unverified. This document must not be interpreted as deployment authorization.

## CI wait-time utilization scheduler — Issue #10 acceptance scope

- When CI starts, pin the PR head SHA and leave an event-driven monitor active; never block a Worker or AI CLI merely waiting for CI completion.
- Schedule **independent review and security analysis of that exact SHA** in parallel with CI, and prepare next-issue specs, tests and deployment/PC/Galaxy acceptance checklists when resources permit. Do not treat speculative or synthetic work as verified acceptance.
- Use separate Git worktrees/branches for mutable tasks. Never modify the CI-tested tree from a concurrent worker or merge an unrelated follow-up into the active PR while its gates run.
- Budget concurrent AI CLI slots based on CPU, memory and token quota; prioritize active PR critical-path work. A pending CI result does not imply idle AI resources are free.
- On CI failure, classify cause and preempt/deprioritize lower-priority tasks; use bounded infrastructure retry or bounded AI correction with fresh-SHA validation. On success, join with the independent-review gate, then proceed only if all acceptance checks match the target SHA.
- Persist task state, source SHA, dependency and scheduling decision in SQLite; after restart reconcile running tasks before any replay. Prevent duplicate dispatch and cap retry attempts as agreed.
- Expose CI state, parallel work, resource occupancy, blockers and SHA-specific evidence on the read-only dashboard, including PC/mobile views.

**Acceptance tests:** CI-running event starts at least two nonconflicting tasks (monitor + independent review), resource saturation defers a third; two writers never share a worktree; failure preempts low-priority work without losing it; restart recovers scheduling state without duplicate actions; CI and independent review both pass on the same immutable SHA before release/merge. Real WSL validation remains mandatory.

**Implementation status:** requirements added; scheduling and live end-to-end acceptance have not been implemented or verified yet.

## Worktree lifecycle and automatic cleanup (Issue #10 mandatory)

- Allocate a dedicated registered Git worktree per PR/AI writer, with a unique task ID, branch, pinned base SHA, approved root directory and owner lease tracked in SQLite. Read-only reviewers must not modify the checkout. Never share writable trees between concurrent AI workers.
- Lifecycle: ALLOCATED -> ACTIVE -> VERIFYING -> CLEANUP_ELIGIBLE -> REMOVED; UNKNOWN/BLOCKED/RECOVERY_REQUIRED cannot be automatically deleted. Retain logs and evidence independently of worktrees.
- Cleanup eligibility requires a terminal task, no live process/lease, completed result collection, all relevant changes safely committed and pushed or otherwise explicitly preserved, and PR merge/closure or an approved terminal cancellation. For an open PR, keep any tree needed for ongoing remediation; idle review-only trees may be removed after confirmed completion.
- Check repository identity, exact canonical path under the managed root, clean Git status, no untracked content, and no linked running task before `git worktree remove` **without --force**. Use `git worktree prune` only to clean stale metadata after validating the registry; never delete arbitrary directories or branches.
- On dirty/untracked changes, uncertain execution status, or failed removal: mark RECOVERY_REQUIRED, record reason and reclaim size, retain data for manual resolution. Do not use `rm -rf`, `git worktree remove --force`, or automatic branch deletion to overcome failures.
- At startup and periodically, reconcile SQLite registry against `git worktree list --porcelain`, recover interrupted cleanup idempotently, and flag orphaned/overdue managed worktrees for safe inspection. Expose cleanup state, active count and disk consumption on the dashboard.

**Acceptance tests:** concurrent writers get distinct trees; failed tasks preserve dirty files; active/unknown tasks are not removed; clean completed review worktrees are removed once; restart does not double-delete; stale metadata is reconciled safely; only approved-root paths are eligible; cleanup errors remain visible without blocking unrelated work.

**Implementation status:** lifecycle/cleanup policy and acceptance criteria recorded; automatic creation, lease management and deletion are not yet implemented or verified in WSL.
