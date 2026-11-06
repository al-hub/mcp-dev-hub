# #35 Protected updater — candidate bootstrap contract (NOT deployed)

This describes the **one-time** privileged transition needed for the
existing immutable controller. It is a proposed contract, **not** a command
to execute and **not** permission to relax OS/GitHub security.

## Non-privileged code already tested in PR #39

- Canonical controller-pair manifest and Ed25519 signed-approval guard.
- Strict durable operation-ID journal and fsynced stage/switch/unknown rules.
- Fixed two-file version directories, SHA-256/byte-length verification,
  single symlink compare-and-swap for `current`, and bounded pointer rollback.
- Candidate transaction coordinator with synthetic two-successful-revision,
  rollback-on-negative-health and unknown-never-replay tests.
- Candidate immutable controller wrapper, designed for the existing direct
  launch contract: the controller executes only when it is the process's
  actual entry script, so a wrapper must spawn the **pinned** controller with
  direct argv (not import it). It executes under the existing **non-root**
  Worker identity. Running the wrapper from a checkout fails closed.

**No production privilege:** All above are source and synthetic/CI tests.
Nothing is installed or callable through sudo on the running WSL machine.

## Mandatory root trust preconditions — BLOCKED until verified

A separately reviewed **fixed root-owned verifier and updater** must:

1. Authenticate an independent approval issuer and pin its Ed25519
   **public** key in root-owned configuration outside the checkout. The
   signing private key must be held by an independently trusted issuer, not
   an Issue, PR, Worker, AGY process or editable checkout. The issuer must
   attest to exact HEAD/BASE, independent Codex **PASS**, required CI success,
   immutable code bytes and the scoped branch-protection policy. Do not
   accept a caller-constructed `proof` object as authenticated evidence.
2. Validate every path ancestor for root ownership, modes and symlinks,
   rejecting user-writable ancestry. Validate the root-owned immutable
   updater's own digest, pinned policy, and release source provenance.
3. Only read bounded canonical request data. Do not accept executable
   paths, shell strings, dynamic arguments, arbitrary repository URLs,
   extra files or changes to trust keys, updater code, policy or allowlist.
4. Before the first switch, snapshot the **existing** root-owned controller
   and policy pair byte-for-byte, verify hashes and stage a recovery version.
   Install the fixed wrapper only after explicit bootstrap authorization,
   with a tested rollback path to the original direct controller.
5. Journal `prepared` and `switch_pending` with durable fsync *before*
   changing the live pointer. Stage only the exact reviewed controller pair
   in immutable version folders and compare-and-swap the single pointer.
   A lost response, lock remnant or partial stage becomes **unknown** and
   demands identifier-based reconciliation, never a second write attempt.
6. Verify owner/mode/hash and Worker/Dashboard/data after switching; on a
   confirmed negative health result perform compare-and-swap rollback
   against the exact old version. Unknown health is **not** negative health
   and must not trigger an automatic rollback or replay.
7. If a privileged launcher is needed, provision only a fixed, root-owned,
   no-arguments updater entrypoint under a tightly scoped administrator
   policy. Never grant a general shell, editor, `node <user path>`,
   wildcards, arbitrary arguments, user-writable scripts, or credential
   access. Do not change global `AI_WRITE=0`, `AI_PUSH=0`.

**Important:** `src/ops/protected-update-transaction.mjs` currently checks
signed claims against a structurally frozen `proof` supplied by its caller.
That is useful for synthetic tests, **but it is not authenticated GitHub
provenance**. A production root entrypoint must **not** use it without the
independent authenticated issuer and fixed root-side adapter above. The
current candidate is **NOT safe to install as a root service**.

## Acceptance and release gates

- Independent security review of the **exact candidate final HEAD** with
  high/critical blockers zero, strict PR CI success.
- One initial, narrowly scoped admin bootstrap **only if** a previously
  trusted install path cannot be demonstrated. No credentials transmitted to
  GitHub/ChatGPT.
- Two **physical** source changes A→B and B→C with user sudo **zero per
  update**, distinct approved HEADs and signed evidence; demonstrate
  integrity, file ownership, stable controller launch, rollback, disconnect/
  unknown recovery and Worker/Dashboard/data preservation.
- Normal protected PR merge, main CI SUCCESS, exact #35 CLOSED readback.
  Only then start #36 acceptance, followed by #37's three separate real E2Es.

The earlier single-file Codex companion repair and these synthetic two
revisions are **not** evidence for either physical protected-file update.
