# #35 protected-update journal foundation — NOT a privileged updater

`src/ops/protected-update-journal.mjs` implements pure state transitions
for an exact two-file update: `prepared → switch_pending → switched →
verified`, or bounded rollback/aborted/unknown states. Durable readback
uses canonical JSON and rejects duplicate keys or malformed state.

`src/ops/protected-update-journal-store.mjs` adds **non-privileged**
Linux file persistence for a *separately trusted* private state directory:
- one journal per fixed-format operation ID, with immutable history;
- exclusive, no-follow `.lock` creation (stale lock is never stolen);
- bounded regular-file readback with owner/mode checks and exact JSON;
- exclusive staged file, fsync(file), atomic rename and fsync(directory);
- an unfinished/unknown operation or leftover staged file blocks new work;
- only verified/rolled-back/aborted revisions permit a later operation.

**Trust boundary:** This module is not installed root-owned, is not invoked
by a trusted root service, and MUST NOT run with root authority merely because
its code exists in a PR/worktree. The eventual immutable root verifier must
independently authenticate the state directory and **every ancestor**, the
GitHub provenance, review independence, CI, trust key, bundled source bytes,
file descriptors and actual OS readback. Mode checks alone are not a sandbox.

Persist `switch_pending` **before** protected filesystem effects. If a
response is lost or a crash leaves a lock or partial stage, the caller must
reconcile immutable identifiers and OS evidence; neither the journal module
nor store authorizes replay or lock removal. Hash equality supplied by a caller
does not establish physical file ownership or service health.

**Still missing for #35:** immutable root-owned updater and signing authority,
authoritative CI/reviewer evidence, fixed allowlisted no-follow protected file
switch, atomic whole-bundle deployment and rollback, trusted crash reconciliation,
negative OS tests, two actual unattended updates, Worker/Dashboard operating
acceptance, and independent final-HEAD Codex security review. These are not
proved by synthetic tests or CI. Gate B–D and Issue #35 remain OPEN.
