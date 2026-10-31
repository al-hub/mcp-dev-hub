# PR completion automation contract (Issue #10)

Goal: one requested PR advances through review, findings remediation, CI, private staging, PC and Galaxy acceptance, and merge without repetitive prompts. A green CI run alone never completes this contract.

1. Identify the exact PR and pin its head SHA; check approved repository, scope and write permissions.
2. Run an independent reviewer, separate from the author, via durable Worker/tmux. Split review into bounded areas. Store each attempt, result and redacted evidence in SQLite.
3. When an attempt fails, first reconcile the existing process and output; do not replay uncertain or still-running work. For verified transient errors, automatically retry at most **three additional times** after 10, 30, and 90 seconds. For auth, access, policy, invalid-input and deterministic failures: BLOCKED with no retry. Preserve the counter across restarts and use transactional compare-and-swap claims to prevent parallel duplicate attempts.
4. Review findings cause bounded code fixes and fresh CI, followed by an independent re-review pinned to the NEW SHA. Prevent automatic approval by the same agent that authored the patch.
5. Stage privately with a service health check and a real authenticated SSE reconnect test. No public exposure or replacement of the production worker on CI success alone.
6. Verify PC and Galaxy access with real acceptance evidence. If direct device access or required approvals are unavailable, set BLOCKED and report the exact missing evidence; never invent a PASS.
7. Merge only when the required independent review, checks, security gates, device acceptance and permissions all pass on the same target SHA. Do not silently merge a moving head.
8. Provide a dashboard progress view and optional manual retry/resume control. Manual controls never reset the max-retry safety limit.

Current status: retry policy helper is implemented and unit-tested, but orchestration, persistence, reviewer result collection, release gates and device acceptance are NOT yet wired to the Worker. This document must not be interpreted as deployment authorization.
