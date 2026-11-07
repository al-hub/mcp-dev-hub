# #35–#37 — one-time privileged bootstrap scope and preflight

> Status (2026-11-06 KST): **NOT READY TO INSTALL**. This document is the
> public, nonsecret **scope freeze and evidence checklist**, not administrator
> authorization, an installer or a claim that unattended updating works.

## Updated real-machine preflight (2026-11-07 KST)

The nonprivileged `scripts/protected-update-bootstrap-readiness.mjs`
now verifies exactly two existing root-owned, mode-0555 controller/policy
files against their immutable Git baseline
`175ba1a481d9a55c0567402a2c905f457c7601e5`, using nofollow and
bounded regular-file reads. The deployed bytes and file sizes match
the corresponding Git blobs **exactly**. It also confirmed the current
controller actually imports and initializes in a real non-network,
read-only Bubblewrap sandbox with no Worker home environment.

**Correction:** the WSL system **already has** `/usr/bin/bwrap`
(root:root, mode 0755, version 0.6.1). The earlier claim that a system
Bubblewrap binary was missing was based on an incorrectly escaped
variable in a shell inventory; no installation is needed for this
dependency. Existing Worker and Dashboard services remain active.

The read-only report intentionally returns
`installerAuthorized:false` and `realProtectedUpdates:0`.
It is **not** an independent signing issuer, root-owned trust setup,
one-shot administrator install script, official approval or evidence
of successful in-place protected update. The remaining gates below
still apply without bypass. Recheck against final reviewed package
HEAD before any eventual owner administrator action.

## Intended result

A single explicitly authorized, narrowly scoped local administrator bootstrap,
**only if an existing already-trusted path cannot be demonstrated**, must cover
all OS privilege needs for the previously approved controller/policy update
capability. Regular in-scope Issue development and verified protected revisions
must thereafter require **zero interactive sudo prompts**. This does **not**
delegate approval for future trust-key, updater, policy, root allowlist,
sudoers or OS privilege changes; these fail closed at *admission*, before a
development job starts, with a precise reason and no unauthorized partial work.

## Read-only operating evidence (2026-11-06 KST)

- Existing authenticated mobile bridge → Termux → strict-host-key SSH →
  WSL read-only command completed with exit 0, returning Linux.
- Existing protected controller, controller policy, Codex, AGY and companion
  are present under the **already documented** root-owned protected directory.
  The directory is root-owned and is not group/other writable.
- Worker and Dashboard each have a running user service.
- The proposed `versions` root, `current` pointer and fixed root evidence
  trust directory were **not installed** at the time of this probe.
- A bounded search of typical system-local executable directories and of the
  existing protected directory did not find a protected updater executable.
  This does not prove no obscure pre-existing OS authorization exists.
- A prior noninteractive `sudo -n -l` check required authentication. That
  result alone does **not** prove every existing narrowly scoped launcher is
  unavailable.
- PR #39 contains a read-only root preflight and synthetic release-switch
  library, **not** an audited/deployed privileged updater or live issuer.
  Existing protected services and credentials were not modified by this audit.

No device hostnames, identities, private addresses or credential contents are
included here.

## Privileged-operation inventory (do not conflate them)

| Operation | When | Authorized boundary |
| --- | --- | --- |
| Inventory of existing protected binary/policy, file hashes, owner/mode and recovery state | Before bootstrap | Read-only, no sudo |
| Install immutable reviewed updater, root-owned public trust anchors, private GitHub API token access policy, protected release layout and *verified original backup* | One-time bootstrap only, if proven necessary | Local administrator; fixed reviewed artifact SHA and bounded command; **never** mutable checkout as root |
| Establish independent review and approval **issuer separation** | Before privileged update | Separate protected principals/keys; not AGY, Issue, PR, Worker or editable checkout; no private key in GitHub |
| Replace exactly two allowlisted controller/policy files via version staging and atomic single-pointer switch | Routine preapproved revision | Fixed root-owned updater only; exact signed manifest/HEAD/BASE, trusted Codex PASS and strict CI, source SHA/size, journal, lock, CAS and verified health |
| Query result, recover after disconnect and roll back a confirmed unhealthy revision | Routine preapproved recovery | Same updater; fixed code, exact operation ID, no blind replay or unknown-as-failed |
| Worker job handling, sandbox tests, scoped git/PR/CI/merge/Issue Close, Dashboard and user-service process management | #36–#37 approved scope | Nonroot Worker and existing service/GitHub identities; no blanket AI_WRITE/AI_PUSH or OS privilege |
| Change updater executable, trusted key, issuer, allowlist, root policy or sudoers, or grant broader OS privilege | Never silently | **New explicit authority and security review**; fail closed before job dispatch |

## Mandatory pre-bootstrap gate — every item must pass

1. **As-built inventory:** inspect existing launcher and *actual* authorization
   (including narrow commands if available), currently running service entry
   points, immutable source hashes, original flat-file baseline, and recovery
   route. Reuse existing permissions before proposing anything new.
2. **Immutable code:** implement fixed, root-owned, no-dynamic-command updater
   and approved source-to-release migration. Protect against ancestor symlinks,
   TOCTOU, user-writeable ancestors, special files, tampered staging,
   arbitrary args/environment, partial writes, concurrent switch and unsafe
   rollback. Separate root side from nonroot Worker; no checkout code as root.
3. **Independent authenticated evidence:** implement and **operate** separate
   reviewer and approval issuers with pinned distinct public keys and protected
   private keys; verify their actual provenance and exact commit/test/review
   evidence independently from the Worker and GitHub Issue text. Audit issuer
   identity, expiration, replay and key rotation fail-closed.
4. **One-time installation package:** predefine exact reviewed binaries,
   immutable digests, root-owned locations/permissions, minimal no-argument
   invocation, backup of the original installed pair, fallback to the original
   direct controller, and safe installer undo. Reject generic shells, wildcard
   sudo rules, `NOPASSWD:ALL`, writable scripts and root network credential
   disclosure.
5. **Verified final HEAD:** strict CI success **and an independent Codex
   security review of the complete final privileged implementation**, with
   actionable high/critical findings addressed. A review of the old
   nonprivileged candidate is not a root-install PASS.
6. **Ready-for-one-time-action decision:** after items 1–5 pass, show the owner
   precisely what the one-time administrator action changes and the
   verifiable recovery path. Passwords and private keys remain local: never
   send them through chat, Issue, PR or build logs.

If any prerequisite fails, report **BLOCKED** and keep the existing protected
runtime unchanged. Do not ask for administrator authentication yet.

## After bootstrap: mandatory physical acceptance

- Verify exact root ownership, file modes, digest, trust policy and initial
  original-release recovery snapshot.
- Perform **two distinct actual protected source revisions** using the
  ordinary unprivileged request path, with zero sudo prompts for each.
- Negatives: wrong SHA/signature, stale base/CI, attacker-controlled checkout
  source, invalid path/symlink/owner, unauthorized file, concurrent update,
  interrupted/unknown state, replay, false health and verified rollback.
- Re-verify running Worker/Dashboard, existing data, OS protection and
  rollback; preserve global `AI_WRITE=0` / `AI_PUSH=0`.
- Merge #35 only via live repository protection and successful exact-head/main
  CI; mark #35 CLOSED **only after** physical evidence. Then implement #36
  generic Issue development and prove #37's **three independent** unattended
  E2Es without additional user intervention.

## 2026-11-07 reproducible source-only package and recovery rehearsal

The current Draft PR #39 provides a **source package candidate**, not an
authorized live root installer. It is intentionally **fail-closed** until
independent operational issuers, pinned review evidence, immutable root policy
and a separately approved installation adapter are ready. In particular, the
candidate bundle manifest sets `installAuthorized:false`, and the fixed
no-argument root entrypoint refuses such a bundle even if two distinct public
keys happen to exist locally. **Do not run the entrypoint as administrator.**

Only after the final candidate Git HEAD is reviewed, an unprivileged WSL
operator can stage an isolated, reproducible private handoff directory:

```sh
node scripts/protected-update-bootstrap-pack.mjs build \
  /absolute/clean/detached/worktree <reviewed-40-hex-head> \
  /absolute/new/private/output-directory
node scripts/protected-update-bootstrap-pack.mjs verify \
  /absolute/new/private/output-directory \
  <independently-pinned-64-hex-manifest-digest>
```

- The builder requires an exact clean Git HEAD, reads only allowlisted
  immutable Git blobs, refuses symlinks, overwrites and dirty worktrees, and
  writes owner-private directories / read-only checked files. It executes
  **none** of the included JavaScript and performs **no privileged action**.
- The checker fails closed on missing external digest, extras, symlinks,
  FIFOs, oversized manifest/source, chmod changes and tampered bytes. Its
  source checksum is **not** a signature or independent security approval.
- A synthetic migration candidate verifies the original flat controller and
  policy bytes before creating a private recoverable backup; only afterwards
  does it stage a two-file version and atomically replace the controller with
  a digest-checked wrapper. Its restore candidate verifies the original
  backup, active baseline and exact wrapper digest before restoring the
  original controller. Crash/unknown stages are preserved and never replayed.
- The separately packaged root entrypoint has fixed OS paths, rejects
  checkout execution and arguments, and refuses the current unsigned/
  source-only package; it is not yet an operating approved updater.
- Unit and integration tests cover **three distinct synthetic
  package→backup→wrapper→original-restore runs**. These are **not**
  the two required live root-protected updates and are not evidence
  of production service acceptance.

**Remaining one-shot install blockers:** an authenticated, issuer-separated
approval for the exact installation package, actual immutable root installer
and least-privilege authorization provisioning, verified as-built original
baseline binding, review of the *complete privileged* implementation, and
post-install owner/mode/hash/rollback/Worker health acceptance. The owner
must not be asked to spend their one administrator action while these
conditions are unsatisfied. The user-facing outcome is **NO-GO**, not
"installation completed".

## Current go/no-go

**NO-GO for administrator installation.** The immutable privileged updater,
independent live issuer trust setup, original-install migration and physical
acceptance are **missing**, regardless of the PR #39 candidate CI result.
Do not spend the user's one-time administrator authorization on incomplete
artifacts. The remaining work is tracked in Issue #35 rather than hidden in
this project-wide constraints document.
