# #35 two-principal signer trust and one-time OS activation — NO-GO

This public document specifies the intended **one-time local administrator**
bootstrap and the independent evidence requirements. It contains **no
secret, owner identity, device path or installation authorization**.
No source checkout may be run as root.

## 2026-11-08 signed Codex provenance gate  source only, NOT DEPLOYED

The candidate issuer previously constructed a PASS and synthetic review run ID
from an official GitHub Bot review text evidence ID. The fixed reviewer and
approval issuers now BOTH require a short-lived canonical Ed25519-signed
independent Codex receipt, tied to the exact PR HEAD/BASE and a deterministic
evidence ID that also binds the immutable package digest. The signer public
key must be owner-pinned independently of the protected reviewer/approval
issuer keys; a mutable checkout or GitHub comment cannot supply it.

Candidate role runners read only fixed root-owned 0444 public proof files
under the separately controlled signer evidence directory. The owner-managed
provisioner requires the pre-approved independent Codex public key before
any user/account side effects; it does not generate or rotate it. No
operational private key, Codex signer, evidence producer or root installation
was created by these source changes.

**Critically, a cryptographically valid receipt only authenticates its
signer. Actual independent Codex execution provenance also requires a
separately audited trusted runner that captures real terminal output and
signs only verified final verdicts. That production runner and trusted
GitHub App APPROVED publisher are not installed. Until both are verified
and the initial bootstrap/recovery is independently accepted, keep NO-GO,
formal review zero, physical updates 0/2 and Issue #35 OPEN.**

## 2026-11-07 source handoff refinement: exact PR #39

The existing GitHub reviewer App publisher previously hardcoded only
PR #17. It now supports **only PR #17 or PR #39**. For PR #39 the
publisher requires an authenticated independent Codex review,
non-Draft exact-HEAD main PR, strict existing gates **plus**
`root_security` and `original_restore` evidence gates.
It rejects arbitrary PR numbers, stale HEAD, missing trusted evidence
and unapproved branch protection. Existing PR #17 behavior is preserved.
The connection preflight similarly permits only these two PR IDs and
does not create another GitHub App or account.

The root signing code has three distinct trust boundaries:

1. An immutable root-owned 0700 bootstrap package with an
   independently pinned manifest digest (source-only, NOT authorized).
2. A separate **root-owned 0555 directory / 0444 immutable 6-file**
   issuer runtime for distinct nonroot signer accounts, prepared by
   the owner-controlled one-shot staging primitive.
3. Root-owned canonical public signing context and a root-only
   orchestrator that independently authenticates exact PR/HEAD/CI
   and the GitHub Bot review and stores BOTH resulting signatures
   in root-only trust files. Unknown/partial output is preserved,
   not retried, deleted or treated as PASS.

Unit and unprivileged full-suite success is NOT evidence of real
privileged signer provisioning or Codex independence; the actual
authoritative proof requires genuine delegated UID/GID execution and
GitHub Codex-approved App review. PR #39 is currently Draft with no
official APPROVED review, and the independent Codex CLI review was
blocked by a quota limit. **Do not run initial sudo setup yet.**

## Current, independently observed facts (2026-11-07)

- Existing flat protected controller/policy match the baseline Git blobs
  exactly; no restoration of the old sources is required before setup.
- Trusted root-owned `/usr/bin/bwrap` exists and successfully imports the
  existing controller inside a no-network, read-only sandbox. No reinstall.
- Worker and Dashboard user services remain running.
- New trust files in `/etc/mcp-dev-hub/protected-update`, immutable
  `protected-updater` package, durable protected journal and narrowly
  scoped sudo policy have **not** been installed.
- GitHub PR #39 remains **Draft** with **no formal GitHub review submissions**
  returned by the repository review API. A successful standalone Codex
  command or unsigned review text cannot substitute for a formal approval
  by a pinned, independent reviewer.
- The independent final-HEAD Codex audit was **interrupted by the CLI usage
  limit**. CLI exit/non-deployed previous reviews are **not** a final
  independent privileged-security PASS. The usage interface indicated the
  next availability at **16:09 KST on 2026-11-07**.
- No privileged source revisions have occurred: **0/2**.

## Reviewed candidate code now in PR #39

| Component | Source | Security scope |
| --- | --- | --- |
| Key provisioning | `scripts/protected-update-issuer-provision.mjs` | One-time root-only, two distinct system users, separate Ed25519 keygen under each dropped UID; private keys never returned |
| Reviewed issuer runtime staging | `scripts/protected-update-issuer-stage.mjs` | Exact six-file read-only root-owned copy of reviewed source; no user-writable imports |
| Reviewer issuer | `scripts/protected-update-review-issuer.mjs` | Separate reviewer UID/GID, own-only key and readonly GitHub credential; independently re-queries strict PR/CI and official reviewer Bot before Ed25519 review signature |
| Approval issuer | `scripts/protected-update-approval-issuer.mjs` | Different approval UID/GID, verifies first signed review, independently rechecks PR/CI and then signs approval |
| Root signed-evidence collector | `scripts/protected-update-issuer-collect.mjs` | Explicit root-only no-arg collector runs each signer under dedicated role UID/GID, verifies both signatures, writes root-only signed attestations, preserves unknown partial state |
| Role isolation | `src/ops/protected-update-issuer-boundary.mjs` | Actual OS owner/group/mode/parent/symlink checks; reject Worker overlap and shared issuer groups |
| Actual review provenance | `src/ops/protected-update-github-evidence.mjs` | HTTPS GitHub official reviewer Bot ID, latest APPROVED and exact commit check; rejects stale/dismissed approval |
| Signed evidence binding | `src/ops/protected-update-install-attestation.mjs` | Distinct Ed25519 signatures binding exact reviewed bundle, commit, CI, baseline and short expiry |
| One-time migration | `scripts/protected-update-bootstrap-entry.mjs` | Pinned root code; signed evidence, actual strict GitHub CI/branch protection and official Bot review before source effects |
| One-time activation | `scripts/protected-update-os-activate.mjs` | Original backup, fixed controller startup health, atomic two-command sudoers installation via real `visudo` |
| Emergency root recovery | `scripts/protected-update-bootstrap-restore.mjs` | Exact byte/hash original controller restoration; not part of routine Worker sudo privileges |
| Routine authorization | `src/ops/protected-update-sudo-policy.mjs` | Exactly two immutable Node commands, `env_reset`, `!setenv`, no shell or wildcard |
| Ongoing update and recovery | `scripts/protected-update-root-apply.mjs` / `scripts/protected-update-root-reconcile.mjs` | Bounded authenticated two-file switch, no unknown replay |

The key-provisioner and installer are **candidate implementations only**.
Their real root behavior, crash recovery and identity provisioning have
not been tested in a privileged OS environment. The private-key generation
program has a compiler/forbidden-path test, **not proof of a successful
real role-owned Ed25519 key installation**.

## Trust principals and owner-controlled bootstrap

A future reviewed, bounded **single administrator session** must, in order:

1. Require an independently pinned **final** manifest SHA-256, complete
   exact-head strict CI and a fresh independent Codex security review of
   all privileged code. Verify the package bytes using trusted OS tools
   **before** executing any of its JavaScript as administrator.
2. Stage only verified Git blobs in the fixed **root-owned non-user-writable**
   package path; check every ancestor, mode, file count and digest.
3. Locally pin root-only baseline hashes, fixed Worker account/UID/GID,
   exact PR/HEAD/CI, approved reviewer Bot ID and GitHub readonly/admin
   evidence token. Tokens/keys remain on device; do not copy into chat,
   PR/Issue, stdout, CI, or a mutable checkout.
4. Use the root-pinned provisioner to create the distinct dedicated
   system identities `mcp35_reviewer` and `mcp35_approver`, with
   no login shell or home directory. Each private key must be generated
   **under its own UID/GID**, stored mode `0400` in its mode-`0700`
   private directory below a distinct root-owned signer base.
   The Worker must have neither key and no authority to invoke
   either signing operation.
5. **Candidate issuance code now implemented, but NOT DEPLOYED:** the
   reviewed exact package is staged into a separate root-owned six-file
   readonly issuer runtime, the reviewer and approval runners operate
   under **distinct** UID/GID/0400 private-key folders, each queries real
   GitHub strict CI/branch-protection and the exact independent reviewer
   Bot over TLS. The reviewer signs first; the approval service
   independently verifies that Ed25519 signature and repeats the live
   evidence checks; the fixed root collector verifies both and stores
   signed proofs as root-only files. This has only synthetic/readonly
   acceptance. No account, token, private key, signer service or root
   collector has been activated.
   The official Bot must FIRST publish an actual APPROVED on exact HEAD
   based on a separately authenticated **real Codex** review. A published
   review evidence ID is not by itself proof of Codex execution; do not
   skip the independently audited Bot publisher's provenance gate.
   A root-approved one-time operator must supply both minimally scoped
   role-readonly GitHub tokens without copying them to the PR/Issue.
6. Only after independently signed review+approval, strict GitHub CI,
   latest official GitHub APPROVED, exact source/baseline and
   unexpired evidence should the installed root activation migrate the
   original controller, check real isolated startup and install the
   two-command sudo rule. Require `visudo -cf` before committing it.
7. Keep the original byte-exact recovery snapshot. Unknown failure
   requires admin reconciliation, **not** automatic unbounded retry or
   stage deletion. The emergency restore entry is not granted to Worker.
8. Verify two distinct real approved root-protected revisions, root
   owner/mode/hash, rollback, disconnect/restart and Worker/Dashboard
   behavior, formal GitHub review, protected merge and main CI **before**
   closing #35.

## Remaining hard blockers

Issuer **source code** and distinct-key handoff now exist in PR #39,
but actual separately operated signer processes, keys/accounts and
readonly GitHub credentials are NOT installed; root trust is absent;
PR #39 is Draft without a formal approved reviewer; an independent
final-code security audit has not passed due to the Codex CLI limit;
actual sudo administrator authorization is not available from the
connected nonroot WSL session.

Therefore **NO-GO for any root installation or activation** at this
checkpoint. The reviewed package explicitly says
`installAuthorized:false`; current tests and manifest hashes do not
override that. Preserve `AI_WRITE=0`, `AI_PUSH=0`, existing services,
data, GitHub protection and Issue #35 OPEN.
