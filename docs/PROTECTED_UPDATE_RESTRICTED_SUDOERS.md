# #35 protected updater — proposed fixed-command sudo admission (NOT installed)

**Security status: NO-GO until separately independently reviewed.** This
document is **not** permission to install a sudoers rule, run mutable
checkout code as root, or grant `NOPASSWD:ALL`.

## Required trust boundary

The one-time owner-authorized administrator bootstrap must verify **every**
condition below BEFORE writing a rule:

- The reviewed package is copied into a **root-owned, non-user-writable**
  immutable location, with exact externally pinned source manifest digest.
  Its Node import closure, trusted ancestors, binary ownership/mode and
  precise startup command are independently audited. Never execute code
  from a Worker checkout, GitHub PR text or arbitrary path as root.
- Root-held token, independent Ed25519 **reviewer** and **approval**
  public keys, signed exact-HEAD review/approval payloads, baseline capture,
  issuer ownership and installer trust are established outside GitHub/Worker.
  The two signing private keys are **operated under distinct principals**,
  not made available to Worker, AGY or a common sudo service.
- The package's `installAuthorized:false` source-only marker is **not**
  equivalent to signed installation authorization. Exact original bytes,
  services and an OS rollback path are independently confirmed.
- Fixed, root-owned `/usr/bin/node`, `/usr/bin/systemctl` and
  `/usr/bin/bwrap` must be available and reviewed. The current WSL
  machine does **not** have a global root-owned `/usr/bin/bwrap`, so
  the sandboxed controller startup observer remains a **NO-GO** until
  this OS prerequisite is safely provisioned.
- `sudo -n` may be used **after** the initial setup only for the two
  exact audited root-controlled JavaScript entrypoints. Signed requests
  on stdin are data-only and cannot choose executable paths, shell
  commands, service names, trust keys, file allowlists or privilege.
- The operating observer verifies service state, exact pair hashes,
  `node --check` AND actual controller ESM initialization inside a
  no-network, no-home, read-only Bubblewrap namespace, running under
  the fixed Worker UID/GID. A missing sandbox yields unknown, never PASS.
- A failed/unknown update is never replayed. The fixed recovery entry
  reads one canonical operation ID, returns only a state classification
  and never mutates a root file or clears a journal lock.

## Exact command shapes (illustrative; not ready to paste)

Both command paths MUST be installed, reviewed and **pinned** before
a sudo policy is considered. The placeholders below are deliberately NOT
valid sudoers syntax:

```text
<approved-unprivileged-worker> ALL=(root) NOPASSWD: \
  /usr/bin/node /usr/local/lib/mcp-dev-hub/protected-updater/code/scripts/protected-update-root-apply.mjs, \
  /usr/bin/node /usr/local/lib/mcp-dev-hub/protected-updater/code/scripts/protected-update-root-reconcile.mjs
```

The final root-owned sudoers file must implement `env_reset`, prevent
`SETENV`/`sudo -E`, and eliminate
`NODE_OPTIONS`, `NODE_PATH`, `NODE_EXTRA_CA_CERTS` and all
unreviewed Node loaders. Its fixed command argv must not accept wildcards,
extra options, arbitrary scripts, a shell or edits of sudoers/updater code.
The exact sudoers syntax and its OS behavior require an **independent
privileged security review and a root-controlled `visudo -cf` check**
before installation; a public template is NOT evidence of enforcement.

The policy must **not** grant generic git, GH, npm, model CLI, node
`-e`, Python, editor, shell or process management as root. The Worker
and Dashboard continue under their existing nonroot services. Preserve
`AI_WRITE=0` and `AI_PUSH=0` globally.

## Physical acceptance after one bounded owner action

Require a fully verified original backup and rollback path, two actual
distinct signed/approved controller-pair revisions, exact file ownership,
real Worker/Dashboard functionality, restart/disconnect ID recovery, a
failed health rollback, rejection of stale/symlink/replay requests,
GitHub formal review/CI and success on main. Synthetic package rehearsals
or CI must **never** be counted as these actual OS acceptance runs.

**Current result: sudoers NOT installed; privileged root updater NOT
deployed; root-protected revisions 0/2; Issue #35 remains OPEN.**
