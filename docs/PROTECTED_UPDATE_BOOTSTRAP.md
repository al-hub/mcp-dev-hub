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


## Authenticated read-only root evidence preflight (candidate source)

The branch now contains a **non-deployed** fixed root-trust reader and
GitHub evidence adapter:

- `src/ops/protected-update-root-evidence.mjs`: rejects non-root callers,
  checks fixed root-owned, non-writable ancestors, reads bounded no-follow
  credential/Ed25519 **public-key** files exclusively from the fixed
  `/etc/mcp-dev-hub/protected-update` location. No caller-supplied token,
  trusted key path, GitHub URL or arbitrary execution input is accepted.
- `src/ops/protected-update-github-evidence.mjs`: fixed TLS GitHub REST API
  origin, fixed repo/workflow identity (`.github/workflows/ci.yml` and
  workflow ID), exact PR HEAD/BASE, required `bootstrap` success, strict
  branch protection, and separately signed short-lived exact-HEAD Codex
  review. Separate pinned reviewer and approval Ed25519 public keys are
  mandatory. The updater's candidate pair source is fetched by **fixed**
  repo content paths and compared byte-for-byte by size and SHA-256 to
  signed manifest values.
- The read-only root preflight combines these with existing signed approval,
  but intentionally has **no installation/switch/sudo/retry entrypoint**.
  Pure test fixtures are not live authenticated evidence.

A future separately vetted root-owned signer/reviewer launcher must issue
the signed approval and independent review attestations. **Their private
keys and GitHub token must never enter the public repository, Worker request,
PR/Issue, or assistant response.** No trust-config directory, key, token,
reviewer-signer, root service, sudoers rule or installer is created by this
PR. The fixed paths are a source contract only.

The real root bootstrap gate remains **BLOCKED** until independently
authenticated identity/issuer policy, immutable code hash, operating update
entrypoint, OS ancestor/TOCTOU review, version migration/recovery and
least-privileged sudo wiring have been reviewed and explicitly provisioned.
Reviewing source code or seeing a successful CI alone cannot authorize it.

