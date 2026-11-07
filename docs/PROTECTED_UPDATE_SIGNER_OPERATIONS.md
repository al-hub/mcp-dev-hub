# #35 two-principal signer trust and one-time OS activation — NO-GO

This public document specifies the intended **one-time local administrator**
bootstrap and the independent evidence requirements. It contains **no
secret, owner identity, device path or installation authorization**.
No source checkout may be run as root.

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
5. **Still to implement and audit:** actual reviewer and approval issuer
   services. They must themselves obtain and authenticate live official
   review and CI evidence, sign only fixed canonical bounded claims under
   their **distinct** private keys, and deliver the resulting public
   signatures to the fixed root trust store. Two separate keys alone do
   **not** prove an independent Codex run. They must never accept
   Worker-supplied `PASS` or an unsigned approval as authority.
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

Actual separately operated **issuer signature services** are absent;
the two role keys/accounts and root trust have not been provisioned;
PR #39 is Draft without a formal approved reviewer; an independent
final-code security audit has not passed due to the Codex CLI limit;
actual sudo administrator authorization is not available from the
connected nonroot WSL session.

Therefore **NO-GO for any root installation or activation** at this
checkpoint. The reviewed package explicitly says
`installAuthorized:false`; current tests and manifest hashes do not
override that. Preserve `AI_WRITE=0`, `AI_PUSH=0`, existing services,
data, GitHub protection and Issue #35 OPEN.
