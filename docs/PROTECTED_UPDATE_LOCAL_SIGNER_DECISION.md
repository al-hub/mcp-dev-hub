# #35 — local WSL protected signer decision (Option C)

Status: **SOURCE-ONLY DESIGN AND TESTED CONTRACT; NOT INSTALLED; NO OPERATING AUTHORIZATION**.

## Owner-approved minimal outcome

Retain the approved, narrowly scoped goal: one authenticated local administrator
bootstrap, then zero interactive sudo prompts per approved protected update.
This **replaces the proposed requirement for separate PC/Galaxy/private-SSE
and root-security Ed25519 device attestations**, but does **not** replace the
actual post-install device tests, root security/rollback acceptance or
independent authenticated Codex code review.

The real #10 precedent was an explicitly documented minimum-scope release
using actual Codex review, CI and operating tests. It did NOT implement
independent signing. The earlier global GitHub mandatory review-rule change
is not a permit to disable other branch protection or self-approve #35.

## Trust and execution boundaries

1. **Untrusted author (AGY/Worker):** may commit proposed code, PRs and tests
   but has no signing private key, root trust file, sudoer edit or unsigned
   release permission. Remote SSH connectivity is not local root authority.
2. **Independent Codex verifier:** a separately operated, immutable OS-owned
   review runner executes real Codex on the exact HEAD, verifies the complete
   terminal verdict against actual source, and signs its receipt. No
   Caller-provided PASS, CLI exit-0 alone, mutable checkout module or Worker
   process is trusted.
3. **Protected reviewer + approver:** two already-designed distinct OS
   identities under the locally owner-approved root trust boundary each
   hold their own Ed25519 key. Neither can read the other's key, the
   Codex signing key or the Worker writeable checkout; each independently
   rechecks current live GitHub PR/CI/protection evidence. The second
   issuer cryptographically validates the first before signing.
4. **Root-owned fixed updater:** a separately pinned, byte-exact immutable
   51-file-or-updated package, original protected two-file baseline, strict
   signed three-role evidence, authenticated CI and owner's one-time
   administrative admission are required before initial activation.
   No caller-controlled paths/shell/argv. Only the original fixed allowlist
   can be changed, with CAS/atomic staging, recovery, replay and UNKNOWN
   rules retained; no general sudo. Do not run checkout code as root.
5. **GitHub reviewer Bot:** under this owner-approved change it is NOT a
   mandatory internal approval producer for the new bootstrap flow, *only
   if* the immutable replacement trust verifier independently enforces
   the protected signed review chain. Actual live GitHub branch protection,
   strict CI and any other GitHub-required reviews remain enforced by
   GitHub itself. No blanket branch protection change is authorized.
6. **Acceptance:** perform two actual distinct signed approved protected
   revisions, failure/unknown/symlink and rollback tests, data and existing
   Worker/Dashboard preservation, private SSE/PC/Galaxy real observations,
   then protected merge/main CI and Issue Close. Device testing is
   decoupled from pre-install **device signature hardware**; no fabricated
   proofs or false physical PASS.

## Implemented source-only guard

`src/ops/protected-update-local-trust-contract.mjs` combines the *existing*
canonical three-principal signed evidence validators for:

- exact HEAD, BASE, baseline source and immutable package digest;
- independently Ed25519-signed Codex complete-run receipt;
- two different Ed25519 reviewer and approver signatures for the same
  review run, PR, CI and original controller bytes;
- current live GitHub CI and protection result supplied **only by an
  independently authenticated fixed root-side HTTPS adapter**;
- short validity bounds and tamper/wrong-key/replay/identity rejection.

It takes no signing keys, keygen, owner password, mutable file path,
`sudo` action or App POST. **It is a pure source-only, synthetic-testable
verification adapter; direct Worker calls can forge the input
`githubEvidence` and therefore MUST NOT be used as a production gate.**
Every successful return explicitly declares `safeToInstall:false`,
`rootInstallerAuthorized:false`, `independentOsIdentityProven:false`
and `safeToMerge:false`.

The **source candidate** now contains a root-pinned `wsl-local-v1`
initial issuer/provisioner/collector, one-shot bootstrap, routine operation
issuer and root-apply source paths. `external-v1` retains the original
Bot/device controls and existing App approval publisher. Local routine
signing authenticates the exact Codex receipt and two OS-separated signed
claims, with root-owned mode, exact CI/protection, immutable two-file update,
replay fences and rollback checks. These candidates are **NOT installed**;
root-owned independent Codex runtime, genuine key isolation and operating
endorsement are not yet verified. Source tests alone do not authorize
privileged installation, source merge or Issue Close.

## Remaining implementation gates — do not claim DONE

- Build a fixed OS-owned, independently managed local Codex review signer
  and two principal role runners, with owner-authenticated key placement
  and live HTTPS read-only evidence; root must independently authenticate
  their provenance, not trust Worker-supplied JSON.
- Verify the **complete** Bot/device replacement path at the final SHA:
  initial issuer/provisioning and bootstrap, local routine issuer, root apply,
  installed signer source, trust/key provisioning and UNKNOWN reconciliation.
  The legacy App-acceptance publisher must remain isolated to `external-v1`;
  actual GitHub-required approval remains mandatory even for C-mode. Do not
  disable a production check without equivalent authenticated, audited proof.
- Add end-to-end RED→GREEN tests for live trust separation, no-op/replay,
  reset/restart/UNKNOWN, distinct real revisions and original rollback.
  Audit all changed privileged imports and fixed-package inclusion at the
  final SHA; a previous HEAD review cannot be reused.
- Obtain only one narrowly scoped **owner-local** admin authorization and
  install verified bytes and strict two-command sudo policy, with the
  trusted source/keys never passing through ChatGPT/Worker/ClosePaw.
- Run actual operating tests, exact CI, authentic final-head independent
  audit, safe merge and close only when all acceptance gates pass.

Existing operating status: **NO-GO** until all mandatory items above are
proven with real evidence. Retain `AI_WRITE=0`, `AI_PUSH=0`, original
service/data, existing branch protection and protected OS files.
