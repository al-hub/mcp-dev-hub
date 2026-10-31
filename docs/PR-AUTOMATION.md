# PR completion automation contract (Issue #10)

Goal: one requested PR advances through review, findings remediation, CI, private staging, PC and Galaxy acceptance, and merge without repetitive prompts. A green CI run alone never completes this contract.

1. Identify the exact PR and pin its head SHA; check approved repository, scope and write permissions.
2. Run an independent reviewer, separate from the author, via durable Worker/tmux. Split review into bounded areas. Store each attempt, result and redacted evidence in SQLite.
3. When an attempt fails, first reconcile the existing process and output; do not replay uncertain or still-running work. For verified transient errors, automatically retry at most **three additional times** after 10, 30, and 90 seconds. For auth, access, policy, invalid-input and deterministic failures: BLOCKED with no retry. Preserve the counter across restarts and use transactional compare-and-swap claims to prevent parallel duplicate attempts.
4. CI failures have their own bounded recovery budget, separate from independent review retries. Classify each failed job before retrying: only confirmed transient infrastructure/network/rate-limit failures may trigger automatic re-runs of failed jobs, up to three additional attempts (10/30/90 seconds). Deterministic test or compilation failures require a code fix and a NEW commit SHA; never burn retries on the unchanged faulty SHA. Record the per-SHA CI retry count persistently and BLOCK after exhaustion. Do not run multiple CI retry controllers at once, or call a fresh push-triggered CI run an automatic retry. This CI controller is a requirement, NOT yet implemented in the workflow.
5. Review findings cause bounded code fixes and fresh CI, followed by an independent re-review pinned to the NEW SHA. Prevent automatic approval by the same agent that authored the patch.
6. Stage privately with a service health check and a real authenticated SSE reconnect test. No public exposure or replacement of the production worker on CI success alone.
7. Verify PC and Galaxy access with real acceptance evidence. If direct device access or required approvals are unavailable, set BLOCKED and report the exact missing evidence; never invent a PASS.
8. Merge only when the required independent review, checks, security gates, device acceptance and permissions all pass on the same target SHA. Do not silently merge a moving head.
9. Provide a dashboard progress view and optional manual retry/resume control. Manual controls never reset the max-retry safety limit.

Current status: OpenCode retry and result-collection helpers have been added to the Worker, but live WSL review and end-to-end orchestration are unverified. CI bounded automatic retry orchestration, release gates, and device acceptance remain unimplemented. This document must not be interpreted as deployment authorization.
