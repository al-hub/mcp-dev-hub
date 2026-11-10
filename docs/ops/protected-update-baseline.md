# Protected updater default — WSL-local independent signing (Option C)

**Status:** Project-level **design baseline** approved for Issue #35 and future
privileged/protected updates. **Not installed or operating-approved.** This
document must never be interpreted as a release credential or as permission
to disable an existing check. Implementation evidence and blockers belong
in the relevant Issue/PR, not in this stable policy.

## Default trust boundary

- **Developer Worker / AGY (untrusted author):** may propose source, tests
  and PRs, but may neither issue independent PASS/approval nor hold or use
  protected private keys or change root-owned trust, sudoers or controller.
- **Independent Codex signer:** a separately operated, pinned OS-owned runner
  completes real exact-HEAD/BASE Codex review, checks a persisted final verdict
  and signs the authenticated review receipt. Model output, CLI exit 0, source
  inspection alone or Worker-supplied JSON is not a production attestation.
- **Protected reviewer and protected approver:** two different isolated
  non-Worker OS principals, each holding its own Ed25519 private key with
  separate owner-pinned public verification keys. The three signing principals
  (Codex, reviewer, approver) must be distinct and verify the same exact
  review run, HEAD/BASE, PR/CI, original baseline and immutable package
  digest. Genuine current GitHub status/protection must be checked over an
  independently trusted, fixed HTTPS adapter, not supplied by the Worker.
- **Fixed root-owned updater:** after one explicit, locally authenticated
  owner bootstrap of independently reviewed byte-pinned code, use only
  fixed allowlisted controller/policy paths and narrowly scoped commands;
  no mutable checkout as root, arbitrary command/args, generic sudo or
  signer-controlled privilege expansion. Subsequent approved updates should
  require **zero interactive sudo per update**.

## What is simplified, and what is not

- No default requirement for separate Galaxy, PC, private-SSE and root
  **external device-signing applications or hardware**. This reduces signer
  provisioning; it does **not** eliminate real post-install Galaxy/PC/SSE
  acceptance, root security checks or proven original restoration.
- An internal mandatory GitHub reviewer-App approval **may** be replaced
  by the above independent, authenticated WSL-local chain **only after**
  the entire immutable privileged implementation, issuer admission, routine
  update path, reconciliation and negative tests have been reviewed and
  verified. Until then, existing App/external signer gates still apply.
  Never weaken live GitHub branch protection or bypass a review that GitHub
  itself actually requires.
- Require exact-HEAD trusted PR CI and protected branch policy, fresh
  signed receipts, baseline/pack authenticity, two-file CAS/atomic
  transaction, symlink/replay/expiry/UNKNOWN fail-closed behavior and
  an independently verified rollback plan. The signed receipt is not
  itself local owner authorization to install.

## Completion evidence and current implementation

- Before first root installation: source tests, privacy inspection, exact
  CI, a genuinely independent final-HEAD Codex audit, authenticated trusted
  signer identities, complete fixed-code dependency closure and a narrowly
  reviewed one-time owner bootstrap. No keys/passwords in AI chat, GitHub
  surfaces, Worker logs or remotely controlled general-purpose shells.
- After installation: **two distinct real protected updates**, original
  rollback/recovery and data, Worker/Dashboard, PC/Galaxy/private-SSE
  acceptance; then normal permitted merge, main CI and Issue Close.
- **Today this is an unimplemented deployment target.** The pure
  three-principal source verification contract is being developed in
  [PR #39](https://github.com/al-hub/mcp-dev-hub/pull/39), but the
  root bootstrap, collector, App dependency and update pipeline have not
  been migrated to it. Existing runtime code remains fail-closed;
  root installation, actual signed operations and closure are **NO-GO**.
  A source-only PASS, draft key, user chat approval or synthetic test never
  promotes these operating gates to PASS.

Reference: [Issue #35](https://github.com/al-hub/mcp-dev-hub/issues/35),
[original signed-contract decision](https://github.com/al-hub/mcp-dev-hub/issues/35#issuecomment-6753443427).
