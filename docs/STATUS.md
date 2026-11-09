## 2026-11-09 #35 App acceptance dual-role boundary and fixed approval issuer (SOURCE ONLY)

- Reused existing PR #39. Actual code HEAD before this status: `6b92daab10172321d58c872a33fd2c67762977b4`, [exact CI #42558684500](https://github.com/al-hub/mcp-dev-hub/actions/runs/42558684500) **SUCCESS**. Nonroot Microduck full Node suite exit **0**, focused combined source/immutable-pack tests **29/29 PASS**, privacy candidate scan **209 files PASS**, `git diff --check` PASS, clean checkout.
- `c1966ba`–`9f8e6d8` move acceptance validity precheck BEFORE creating a crash-durable GitHub App POST intent. Expired independent acceptance must not consume an unused submission ID; actual dispatched/UNKNOWN POST remains permanently fenced. Focused rejection/concurrency tests passed.
- `cf70ea6`–`f6df2de` require **two distinct Ed25519 signatures** on the same canonical short-lived, exact HEAD/BASE/CI/pack App acceptance packet: independently pinned reviewer key and separate approval role key, each with its own domain. No same-owner JSON + checksum or sole approval signer can assert independent origin. Root fixed App entrypoint checks both before App API and at POST/final readback.
- `95fb714`–`6b92daa` add an **UNINSTALLED fixed no-arg approval-role signing candidate**, restricted to the previously isolated nonroot approval UID/GID/private key and a literal immutable role path. It consumes an already reviewer-signed root-staged acceptance handoff, actual separately signed Codex PASS, current verified GitHub strict CI/branch protection, and physically reads the original root-owned controller pair for exact bytes-vs-GitHub baseline comparison. No generic signing API, caller-supplied key/path, new account, install, sudo policy, App POST or physical protected update is added. Source-only execution refuses to sign and exits 78.
- **Still SOURCE/PROVENANCE BLOCKED:** the independent REVIEWER acceptance issuer and authenticated evidence producer/provisioning path for the real PC/Galaxy/private-SSE/root-security/original-restore gates remain **unimplemented**. Existing `pr_gate_evidence` database records are not independently signed by themselves. No real reviewer-signed packet, approval role operating signature, root-sourced durable evidence archive or approved installation exists; these cannot be synthesized or treated as PASS. The new fixed approval signer would reject an absent handoff. The earlier actual WSL Codex attempt is **INCOMPLETE** (usage limit, exit 1, no persisted final verdict), not PASS.
- Formal PR reviews **0**, physical protected updates **0/2**. Gate A/B **BLOCKED**, C/D **NOT_TESTED**; PR39 OPEN/unmerged, Issue35 OPEN. Do not bootstrap, issue App APPROVED, merge or close until independently authenticated producer and fresh exact-final-HEAD Codex PASS/receipt are available. No root/keys/trust/OS accounts/service/data/branch protection change. `AI_WRITE=0`, `AI_PUSH=0` preserved.

## 2026-11-09 #35 fail-closed independent App acceptance signature (UNINSTALLED)

- PR #39 source checkpoint before this STATUS update: `b39d07607b6be9c0ace56e34a6d2f691ad0a5627`; [exact-HEAD CI #42554756439](https://github.com/al-hub/mcp-dev-hub/actions/runs/42554756439) **SUCCESS**. The existing per-operation routine signing pipeline is unchanged and remains uninstalled.
- Fixed the App publisher's previous acceptance boundary: a root-owned `app-acceptance.json` plus independently unproven root-owned SHA-256 is no longer sufficient for the accepted packet. The new verifier requires the canonical v2 packet's **fresh, domain-separated Ed25519 signature** from the existing distinct root-pinned approval public key. It binds the exact PR39 HEAD/BASE, CI run ID, immutable pack digest and entire evidence/protection payload, with a 120-second maximum lifetime. The fixed App entrypoint revalidates before approval POST and final result.
- The immutable source-only pack includes this verifier. New synthetic negative tests reject unsigned/forged/wrong-key/stale/noncanonical/wrong-HEAD-BASE-CI-pack/wrong-role packets. Local Microduck focused tests **5/5 PASS**, full Node suite **exit 0**, source package tests **16/16 PASS**, privacy scan **207 files PASS**, whitespace diff check PASS, source-checkout App entrypoint **exit 78** (denied). GitHub CI is distinct from operational acceptance.
- **Still NO-GO:** no independent issuer-produced, signed acceptance packet/provisioning channel has been installed or tested. Signatures cannot be fabricated by root or Worker; the existing approval signing role is NOT automatically authorized to sign the new domain. The last actual WSL Codex final-HEAD audit remained INCOMPLETE due to usage limit; no signed final PASS, no genuine Bot APPROVED, no privileged bootstrap and no physical root updates (0/2). PR39 and #35 must remain OPEN, Gate A/B BLOCKED, C/D NOT_TESTED. No sudo, keys, services, protected files, data, or branch policy changed; AI_WRITE=0 and AI_PUSH=0 remain.

## 2026-11-09 #35 routine issuer source integration + durable UNKNOWN reconciliation (UNINSTALLED)

- Existing PR #39, exact source HEAD `738a8df733e123b9d15ef5d0b6af6ef5de1338ff`. Following the prior `faa20ab` checkpoint, source-only changes `faf336d`, `76741f7`, `8321614`, `e48803c`, `b5b312d`, `7c2f29a`, `2990227`, `4f09349` and `738a8df` implement **non-authoritative** routine controller-pair operation intent validation, independent reviewer/approver signature collection, exact signed Codex/Bot/CI/manifest/pinned-key checks, root-owned per-operation staging, durable non-replayable dispatch and signed request archive, and read-only lookup of incomplete/UNKNOWN issuance. Existing immutable root apply and prior journal/reconcile flow are reused. A global routine issuance fence remains on UNKNOWN and is released only after a definitive verified/rolled-back protected transaction. Source-only checkout execution refuses root privilege.
- The final source commit [CI #42542593901](https://github.com/al-hub/mcp-dev-hub/actions/runs/42542593901) **completed SUCCESS**. Direct Microduck nonroot full Node suite **exit 0**, candidate privacy check **205 files PASS**, focused root/signing/recovery tests PASS and `git diff --check` PASS. A separate nonprivileged exact-HEAD source pack build returned `source_only_unprivileged_no_go` with **47 pinned files**. The source bundle hash is only a checksum, **not** an independently authenticated installation approval.
- This source work is **NOT** a real operating signer installation, WSL root exercise, GitHub App approval or privileged acceptance. No actual reviewer/approval signatures, trusted App acceptance packet, root operator activation, protected physical updates, rollback or main merge were produced. The candidate design still needs an **independently authenticated acceptance-packet producer/provisioning channel**, exact-final-HEAD independent Codex security PASS, verified operating signer/App identities and installation authorization before production. The last actual WSL Codex attempt was **INCOMPLETE** (CLI usage limit, exit 1, no final verdict) on prior source; it is **not** carried forward as PASS or a fresh FAIL. No ungrounded retry.
- **Gate A BLOCKED; B BLOCKED; C/D NOT_TESTED.** Real GitHub PR #39 reviews **0**, physical protected updates **0/2**, PR39 OPEN/Ready/unmerged, Issue35 OPEN. No root install, sudo/key/trust/policy change, service restart, approval POST, branch-protection modification, merge or data deletion; `AI_WRITE=0` and `AI_PUSH=0` unchanged. Next safe action is independent source audit and authentic App acceptance provenance, NOT root bypass or synthetic gate PASS. Any operator action is conditional on these gates.

## 2026-11-09 #35 trusted App publisher + durable POST fence (UNINSTALLED)

- Reused PR #39 and unchanged protected execution/identity boundaries. Source commits `a2aba3d5531c2ea696d588e5c74578554ac16f3c` and `cc997aa226ca9aa0e9b9b32695a9aa3cac84a5b8` add a fixed root-path publisher using the existing App, root-pinned source pack, independently approved acceptance-packet digest, separately signed Codex receipt and existing root key/read-token pins. It independently refetches CI/protection before App key access. This is uninstalled candidate code, not an approval or grant.
- The publisher wraps the existing scoped App client with an exclusive fsynced HEAD/BASE intent before an approval POST. Restart, concurrent caller, changed evidence, timeout or malformed POST response cannot resend; existing genuine approvals can only be reconciled by the existing live readback. Intent and API response are separate records, never a fabricated confirmed approval.
- Focused publisher/fence tests **20/20 PASS**; actual nonprivileged WSL full Node suite exit 0; candidate privacy scan **194 files PASS**; diff whitespace check PASS; source-checkout direct publisher invocation correctly denied with exit **78**, no stdout. [Exact source CI #42537995121](https://github.com/al-hub/mcp-dev-hub/actions/runs/42537995121) **SUCCESS**, `npm run check`: **436/436 tests PASS**, privacy **194 files**. Microduck MCP lacks npm in PATH; no PATH/service changes were made and the Node/privacy checks were run directly there.
- Actual configured SSH path was read from existing configuration and validated through the Windows host into WSL; installed protected Codex **0.166.0** ran against an isolated exact-source checkout. Independent final-source audit **INCOMPLETE**: Codex exit **1**, usage-limit error, **no final verdict file**. The outer command returning 0 is not audit PASS. No blind audit retry, signed receipt or Bot review was produced. GitHub reviews API **0**.
- **Remaining source blocker:** trusted per-operation root context staging, independent role dispatch, signature collection and durable receipt/archive lifecycle for successive routine controller-pair updates remain unimplemented. The new App driver also still requires an independently authenticated acceptance-packet producer/provisioning path; root ownership or a self-written digest is not independent evidence. No final-head independent security PASS exists.
- **Gate A BLOCKED; B BLOCKED; C/D NOT_TESTED.** Actual protected updates **0/2**; no root installation, key/trust/sudo changes, service restart, approval POST, merge or Issue Close. Preserve original controller/policy, private job/data history and AI_WRITE=0 / AI_PUSH=0. No immediate owner action can safely replace the missing source/evidence gates.

## 2026-11-08 #35 pinned installed Codex executable size preflight (SOURCE ONLY)

- Read-only ClosePaw→Termux→existing SSH alias→WSL returned `Linux`/exit 0. Root-owned installed Codex CLI and companion executable metadata were observed at **319346888** and **77997328** bytes respectively; both exceed the candidate independent Codex runner's previous 64 MiB metadata cap. The protected executable size condition would deny before any independent model invocation even when ownership, modes and SHA-256 were correct.
- On existing PR #39, refactored both initial metadata and streaming-hash preflight to share `supportedProtectedExecutableSize`, then narrowed the upper bound to **384 MiB**. Existing root owner, 0755, single hardlink, nofollow and exact SHA-256 checks are **unchanged**. The update does not access any key or permit unchecked executable bytes.
- New regression verifies recorded installed sizes and rejection of zero/negative/fractional/non-numeric/oversized files. Before fix, focused tests **6/7 PASS, 1 FAIL**, after source fix **7/7 PASS**; full Node suite **exit 0**, privacy candidate check **185 files PASS**, `git diff --check` **PASS**. Microduck #35 workspace clean; code/test checkpoint `a88caace76415aa73a4dbcc0054f4c0a59a204e7`.
- Live protected updater installation path remains **absent** and existing independent final-audit signed receipt was **not found** at the candidate path; the trust directory could not be read by the unprivileged observer (permission denied, **not proven absent**). A read-only process-name query found no active process named `codex` at that instant, but does not recover the earlier incomplete 105-second audit or prove its final verdict. The current separate WSL worktree did not contain the exact PR39 source object; no unsafe checkout execution or blind audit retry was performed.
- The owner's present one-time bounded approval does not itself create operational signer principals, root trust anchors, a valid independent final-HEAD Codex PASS, authentic App APPROVED or an authorized install packet. **NO-GO for root bootstrap** pending these independently verified gates; physical protected updates **0/2**. Keep PR39 OPEN/unmerged and #35 OPEN. #36 remains source-only, #37 0/3; `AI_WRITE=0`, `AI_PUSH=0`, branch protection, services, keys and private DB unchanged.

## 2026-11-08 #35 Bot endorsement evidence marker fail-closed (PR #39, source only)

- Corrected the existing live GitHub Bot review validator: a genuine same-HEAD `APPROVED` with a missing or malformed independently verified publisher evidence marker is no longer returned as `official_github_bot_review_confirmed`. The strict evidence-body syntax already required by the scoped App publisher now also applies to root-side GitHub review readback; no review is posted.
- Source/test checkpoint `a631244e040b1c30524c065ed3818556932dbb46`. Microduck focused endorsement tests **7/7 PASS**, full Node suite exit 0, privacy candidate scan **185 files PASS**, `git diff --check` PASS. Final documentation HEAD still requires its own GitHub CI confirmation.
- **Uninstalled / NO-GO.** This is additional negative validation, NOT authenticated Bot APPROVED, not evidence of a completed independent Codex privileged audit, and not a deployed root verifier. Final-head Codex PASS, distinct operational signer/App identities, user-authorized minimal root bootstrap, two real protected updates and rollback acceptance remain absent. PR39 OPEN/unmerged; #35 OPEN, physical updates **0/2**. AI_WRITE=0 / AI_PUSH=0, original Worker/Dashboard/root assets and branch protection unchanged.

## 2026-11-08 #35 independent Codex execution receipt runner CANDIDATE — NO-GO

- Reused open PR #39 and the existing signed-receipt verifier. Added
  `src/ops/protected-update-codex-terminal.mjs` and a separate fixed-path
  nonroot `scripts/protected-update-codex-receipt.mjs` source candidate.
  The runner requires a root-staged immutable HEAD/BASE review packet,
  SHA-256 of review input and exact root-owned Codex, companion and
  Bubblewrap binaries, a dedicated nonroot signer key and bounded read-only
  isolation. Neither the Worker nor arbitrary CLI arguments can supply PASS.
- The runner records its one-time attempt before dispatch. Only a real
  process with successful status AND a separately persisted canonical
  final PASS for the same HEAD/BASE may produce a short-lived Ed25519
  receipt under the established independent Codex signature domain.
  Failure, timeout, missing final verdict, untrusted checkout or unknown
  outcome fails closed, preserving state without automatic replay.
- Source-only package includes both new files with static import closure.
  Exact source HEAD `a84a515e2bf5b66ef624e9333daf9760a2c6ab9f`:
  [CI #42441436313](https://github.com/al-hub/mcp-dev-hub/actions/runs/42441436313)
  completed SUCCESS, Node tests **414/414**, privacy scan **185 files**.
  Earlier privacy scanner flagged literal sandbox HOME in source; the
  exact expression was made synthetic while preserving the scanner.
- **Not deployed and not independently security-approved.** No operational
  Codex role/key/credential, owner-pinned source packet, audited installation
  or actual signed real-model result was created. Existing protected
  reviewer App key/auth evidence reused conceptually, not accessed.
  Fixed trusted App production publisher and separately authenticated
  root-security/original-restore evidence remain absent. Official GitHub
  reviews 0, real protected updates 0/2, root rollback/unknown and
  Worker/Dashboard post-install acceptance untested. No sudo/root, key
  creation, installation, service restart, GitHub review POST, policy change,
  merge or Issue Close. CI is not deployment authorization.

## 2026-11-08 #35 signed Codex proof mandatory in App publisher — SOURCE ONLY

- Existing PR #39 only: the non-privileged publisher library now requires
  a fresh, canonical independent Codex Ed25519 receipt on exact PR39 HEAD
  and BASE, distinct signer public keys supplied from an out-of-band
  pinned trust boundary, and the exact immutable package digest-derived
  evidence ID BEFORE any GitHub App API call. An actual GitHub PR BASE
  mismatch also fails before APPROVE. Existing PR17 behavior is preserved.
- Added synthetic negative tests rejecting missing/forged/stale/mismatched
  signature keys, unrelated package/evidence IDs and moved PR base.
  Source/test commit 9aace760; exact-HEAD GitHub CI 42440188549 SUCCESS.
- This cryptographic binding does NOT prove the independent Codex process
  actually ran: no fixed, independently operated execution-to-receipt
  signer has been installed/audited. The root-owned App caller with live
  pinned key provenance, scoped PR-write token, official Bot APPROVED,
  privilege audit, root trust/updater and two physical updates (0/2)
  likewise remain unverified. No root/sudo, services, secrets, existing
  App credentials, branch policy or data were changed.
- NO-GO: do not invoke approval or protected installation until the
  fixed audited receipt producer and trusted publisher are installed,
  fresh exact-final-HEAD independent privileged-security GO is obtained,
  and the owner separately authorizes a minimal bootstrap.

## 2026-11-08 #35 Bot review-to-proof binding — SOURCE ONLY, NO-GO

- Existing PR #39 only: the fixed-scope GitHub App review publisher now
  refuses to reuse or confirm a same-HEAD Bot APPROVED for PR #39 unless
  its actual GitHub review body names the exact independently verified
  evidence ID supplied to this invocation. Added two synthetic fail-closed
  regression tests (mismatch and missing evidence body). Prior valid
  same-HEAD evidence is not implicitly transferable to a new proof.
- This correction does NOT install a trusted publisher, produce an
  independent real Codex execution receipt, authenticate the installed App
  in a protected publishing context, or submit an official approval.
  Source CI at the resulting final HEAD and a new real independent
  privileged-code audit must be checked separately. Root trust, signer
  accounts, restricted sudo, physical updates (0/2), rollback and
  protected merge remain unaccepted. Keep Issue #35 OPEN and PR #39 unmerged.

## 2026-11-08 #35 signed Codex provenance hardening  SOURCE ONLY

- Existing PR39 WSL isolated worktree: reviewed P2 root supplementary-group
  cleanup pushed in a separate tested commit; previous full Node tests
  401/401 and independent read-only Codex P2 diff audit PASS.
- Candidate root issuer now requires a canonical, short-lived Ed25519-signed
  independent Codex receipt and exact package/HEAD-bound Bot evidence ID
  before either signer can construct a PASS. Synthetic issuer/collector
  verification tests 12/12 PASS. Full CI and final-source audit still pending.
- The independent receipt producer, trusted reviewer App production publisher,
  root-owned activation, real signers and two physical updates remain
  uninstalled or unverified. No new credentials or root changes. NO-GO
  for privileged installation/PR merge/Issue #35 Close.

## 2026-11-07 #35 trusted GitHub App preflight candidate — NOT DEPLOYED

- Reuse the existing installed reviewer App and its original owner-protected key. No credential or global repository policy change.
- `scripts/reviewer-app-trusted-preflight.mjs` is source-only: it can authenticate ONLY from the independently hash-pinned fixed root-owned package path, with a root-owned 0400 configuration and an existing root-owned 0600 key under the existing private directory. It discovers the exact repository's installation and checks PR #39 HEAD/actor without posting any review.
- This is a protected owner bootstrap **candidate**, not a grant to execute checkout files as root. It must not run with root privileges before an independent installation review and one separately authorized owner action. No operational App exchange or independent reviewer attribution is yet claimed.
- The existing updater signer accounts, root trust, two-command sudoers and real protected updates are not provisioned. PR #39 and Issue #35 remain OPEN; an actual Bot APPROVED, separate issuer identities/signatures and 2 genuine unattended revisions are still mandatory.
- The package manifest includes the two pinned source dependencies used by this preflight; its `installAuthorized:false` remains mandatory.

# Handoff status

## 2026-11-07 #35 PR #39 independent proof and real issuer-runtime handoff — NO-GO for root

- The **existing Draft PR #39** is reused; no root auth, sudo changes,
  installed signing principal/private key/token, protected controller update,
  Worker DB/keys, service restart or global AI_WRITE/AI_PUSH change.
- Reused the **existing GitHub reviewer App** code (no new GitHub App/account):
  `src/jobs/github-app-review-publisher.mjs` and
  `scripts/reviewer-app-connect.mjs` now accept only PR #17 (existing)
  or #39. #39 requires **non-Draft exact HEAD**, trusted real independent
  Codex, strict existing CI/security/user acceptance PLUS `root_security`
  and `original_restore` gates, official GitHub decision and no
  unknown POST replay. It refuses arbitrary PR IDs and stale HEAD.
- Added actual issuer-candidate entrypoints
  `scripts/protected-update-review-issuer.mjs` and
  `scripts/protected-update-approval-issuer.mjs`; each ONLY operates from
  an OS-fixed root-owned issuer-runtime path under its own nonroot
  UID/GID/private Ed25519 key. Each independently queries actual GitHub
  strict CI, branch protection and latest exact-HEAD pinned Bot
  **APPROVED** (including its verified review-evidence ID). Approval
  validates the first Ed25519 reviewer signature and review-run ID
  again before constructing its own second signature. Unknown, expired,
  stale, forged, wrong-key and caller-supplied PASS are denied.
- Added `src/ops/protected-update-bootstrap-issuer.mjs` for exact
  canonical two-stage Ed25519 claims, plus
  `src/ops/protected-update-issuer-runtime.mjs` for fixed OS mode/owner/
  symlink/private-token checks; tests prove two separate keys produce
  claims accepted by the earlier root verifier and reject impostors.
- Added `scripts/protected-update-issuer-stage.mjs` to copy an
  externally pinned, root-owned 0700 source-only package's **exact
  six-file static import closure** into a separate root-owned 0555
  runtime whose files are 0444, never the Worker checkout.
- Added `scripts/protected-update-issuer-collect.mjs`: fixed no-arg
  root-side handoff that independently checks GitHub, runs role scripts
  under their respective UID/GID, verifies both Ed25519 signatures,
  writes canonical handoff/root-only trust files and preserves unknown
  partial state rather than retrying/deleting it. The one-time
  `scripts/protected-update-issuer-provision.mjs` now derives
  root-owned public context from pinned original package/baseline and
  copies each **separately scoped readonly GitHub token** into the
  respective mode-0400 role private directory. Tokens, passwords and
  private keys are never returned/logged.
- Actual nonroot WSL **382/382** full Node `.test.mjs` suite PASS,
  privacy scan **180 files PASS**, both Worker/Dashboard **active**.
  [Exact-code-head strict CI #42345604627](https://github.com/al-hub/mcp-dev-hub/actions/runs/42345604627)
  completed **SUCCESS**, **386/386 tests PASS, 0 FAIL**, privacy
  candidate scan **180 files PASS**. Subsequent documentation-only
  HEAD `ccd61f6593f19081add64b8897fe943cc2ed9e12` also has
  strict CI **SUCCESS #42345793813**.
- **Important:** No genuine reviewer Bot APPROVED is present for
  Draft PR #39; no separately operated reviewer or approval signer
  is yet installed. The App's legacy trusted review provenance
  verifier must itself be operationally audited, so a textual evidence
  ID is NOT an independent proof of Codex execution. Independent
  Codex privileged source audit was interrupted by quota; exact-final-
  HEAD PASS NOT obtained. Source-only `installAuthorized:false` and
  actual protected revisions **0/2**, #35 OPEN, PR #39 Draft.
- The independent review can be retried after the previously reported
  quota reset; a 16:15 KST follow-up was previously arranged.
  **Do not attempt sudo setup before actual signed reviewer/App
  provenance, complete privileged audit and one owner-authorized OS
  bootstrap.** All operating root/trust/stage changes remain
  unapplied and must be tested in the real OS before accepted.

## 2026-11-07 #35 one-time signer provisioning, root activation and real visudo checks — NO-GO

- Continued development in the **existing Draft PR #39**, without root or
  sudo operations, trust/credential/Worker DB changes, service restart,
  global `AI_WRITE=0`/`AI_PUSH=0` relaxation or branch protection bypass.
- Added `scripts/protected-update-bootstrap-restore.mjs`: fixed root
  emergency restore entry (not granted via routine sudo), exact pinned
  original controller backup/hash recovery with no unknown replay.
- Added `src/ops/protected-update-issuer-boundary.mjs` and
  `scripts/protected-update-issuer-provision.mjs`: two **dedicated distinct
  OS identity** key-owner candidates. Each Ed25519 private key must be
  generated under its own dropped nonroot UID/GID with mode `0400`
  in a role-owned mode-`0700` directory beneath the separate root-owned
  signer base. No private key bytes are returned; any existing
  key/account/partial stage fails closed. **No actual accounts or keys
  were created on this operating host.** The static child keygen program
  passed syntax and arbitrary-path denial tests.
- Added `src/ops/protected-update-sudo-policy.mjs` and
  `scripts/protected-update-os-activate.mjs`: candidate one-time
  root-only activation after externally pinned package, distinct
  signer/approval/strict GitHub proofs, verified original backup and
  real sandboxed controller startup. Sudoers permits **exactly two**
  fixed root-owned Node entrypoints, no shell/wildcards, `env_reset`/
  `!setenv`; actual WSL `/usr/sbin/visudo -cf` of synthetic
  generated policy **PASS**. No sudo policy was installed.
- Added pinned **official GitHub reviewer Bot** approval validation
  for the exact PR/HEAD, including rejection of stale/dismissed/
  foreign reviews. The actual PR #39 formal review API returned
  **0 reviews**, so independent official APPROVED is still missing.
  Running a Codex command or seeing green CI alone does not meet
  that requirement.
- Actual WSL tests on source HEAD
  `39b42851a8e95548c96c38021e736eab9462e089`:
  **351/351 PASS**, privacy candidate scan **168 files PASS**,
  Worker and Dashboard user services both **active**. Corrected
  an earlier flaky synthetic signature tamper test to guarantee an
  actual changed byte.
- Exact-HEAD [GitHub strict CI #42342740405](https://github.com/al-hub/mcp-dev-hub/actions/runs/42342740405):
  **SUCCESS**, **355 tests PASS / 0 FAIL**, privacy candidate scan
  **168 files PASS**.
- Three independent 26-file, immutable-Git-blob **source-only**
  bundles produced matching manifest SHA-256
  `9ab59c1f8ceed4ada1ed452599ba4de8ae9cd2ed47cb6bfce1ef02c7e5f0e486`.
  All remain explicitly `installAuthorized:false`. Hash equality
  is not an approval signature or a privileged installer proof.
- Independent Codex final privileged-source review was attempted
  but **interrupted by the CLI usage limit**; no final PASS.
  A retry after the indicated 16:09 KST quota reset is necessary.
- **Unfinished blocking prerequisites:** independently operated,
  provenance-verifying reviewer+approval signature **issuer services**
  (not just different key verifier code); actual root trust/
  dedicated signer key provisioning; immutable staged initial installer
  with explicit single bounded owner administrator action and full
  privileged OS audit; actual protected revisions **0/2** with
  physical rollback/disconnect proof; formal GitHub APPROVED,
  PR merge/main CI, Issue #35 Close. This work **does not complete**
  root installation or achieve unattended root updates. PR #39
  remains Draft and #35 OPEN.

## 2026-11-07 #35 live nonroot baseline and sandbox acceptance — corrected OS inventory

- Existing Draft PR #39 and isolated clean WSL worktree reused; no root/sudo
  action, no signer/key/privilege/service configuration change.
- Corrected a prior **false blocker**: actual operating
  `/usr/bin/bwrap` is **present**, `root:root` `0755`,
  v0.6.1. The previous check mistakenly treated an escaped shell
  variable as a literal path. **Do not reinstall Bubblewrap.**
- Read-only exact installed originals:
  controller `14357` bytes SHA-256
  `595d6c5180abf82f2ecb50534a7a2e6d70c7f9f3395135082b2cc881be77231e`,
  policy `7887` bytes SHA-256
  `a2b81bca5d27a50a9a84d11d9240ee4ab85f1b07695a0fbc2c44d2e6a61dd839`.
  Both are `root:root` `0555`. These match exactly the two immutable
  Git blobs from original baseline commit
  `175ba1a481d9a55c0567402a2c905f457c7601e5`.
- Added `scripts/protected-update-bootstrap-readiness.mjs`,
  **nonprivileged/read-only** before any administrator action. It
  independently compares exact Git object bytes against real protected
  root files, checks fixed directory ancestry, nofollow regular-file
  bounds and owner/mode, and actually imports the existing protected
  controller under the genuine **root-owned, no-network, read-only,
  no-home Bubblewrap namespace**. Actual WSL result:
  `original_baseline_and_isolated_startup_confirmed`,
  `installerAuthorized:false`, `realProtectedUpdates:0`.
  Readiness fixture negative tests **5/5 PASS**.
- This removes **baseline ambiguity and the missing-Bubblewrap blocker**,
  but creates no trusted independent signing principals, no immutable
  root installer or narrow sudoers, and no physical protected updates.
  Source candidate remains uninstalled and source-only
  `installAuthorized:false`.
- **NO-GO for one-time administrator install until** separate operated
  reviewer+approval private signers, pinned root trust and
  verified owner-approved immutable installer/undo are completed.
  Physical protected updates **0/2**, Issue #35 OPEN, PR #39 Draft.
  Real Worker/Dashboard services remain active and original bytes untouched.

## 2026-11-07 #35 root updater / issuer-bound bootstrap admission candidate — NOT INSTALLED

- Reused Draft PR #39 without touching main, Worker/Dashboard, privileged trust
  files, keys or global AI_WRITE/AI_PUSH policy. The authenticated mobile
  Bridge→Termux→SSH→WSL path was usable and both existing user services were
  **active**.
- Added separately signed Ed25519 **reviewer** and **approval** attestation
  binding for exact bootstrap package SHA-256, HEAD/BASE, PR, CI, original
  baseline hash, review-run ID and short expiry. The two public keys must be
  **distinct**, pinned from immutable root config; payload role crossover,
  signature substitution, replay/expiry and stale evidence fail closed.
  The signed claims are cross-checked against **actual fixed GitHub HTTPS
  PR/CI/main-branch protection**, never treated as self-authenticating.
  These are **cryptographic verifier candidates**, not operating signers.
- Added fixed, zero-argument, root-only protected update and read-only
  operation-ID reconciliation entrypoint candidates. Only exact signed
  controller/policy pairs are eligible for staged single-pointer CAS,
  durable journal and bounded rollback; unknown outcomes remain nonreplayable.
  No generic shell, path, sudo, reviewer key or command from Issue/Worker.
- Added pinned Worker/Dashboard health checks and a fail-closed requirement
  for actual controller ESM import/initialization inside a no-network,
  no-Worker-HOME read-only Bubblewrap namespace as a nonroot Worker.
  **A globally root-owned `/usr/bin/bwrap` is currently ABSENT on the
  operating WSL host**, and it cannot be silently substituted with a
  user-writable executable. One-time reviewed OS provisioning is required.
- Real independent Codex reviews on intermediate source commits reported
  **P2 false startup-health PASS**, **P1 mistaken effective-GID check**, and
  **P2 stale signature clock** in both root update and one-shot bootstrap.
  All were corrected in source, and negative/clock/review-role tests were
  added. A *fresh exact-code-HEAD security review* is required before
  installation; a synthetic test or a Codex exit status alone is not a
  privileged operating acceptance.
- Read-only WSL Node tests on latest source code `74bb5281a8e436b0234e47a549ff69e65725a825`:
  **310/310 PASS**, privacy scan **PASS**. Earlier source HEAD had
  **three consecutive 310-test WSL suites = 930 PASS** and three
  reproducible **21-file source-only** packages with matching digests.
  Exact code-head [strict CI #42337508014](https://github.com/al-hub/mcp-dev-hub/actions/runs/42337508014)
  **SUCCESS**: `bootstrap` 314 PASS, 0 FAIL, privacy scan 155 files PASS.
  Worker/Dashboard remained active around these tests.
- **NO-GO for owner sudo/administrator installation:** independently
  operated review/approval signer keys and issuer separation, audited
  immutable OS one-shot installer and original-backup trust setup,
  global root-owned bwrap, installed root updater and exact sudoers command
  policy, complete privileged audit and real physical protected source
  updates **0/2** remain. Current source-only manifest intentionally sets
  `installAuthorized:false`. #35 OPEN, PR #39 Draft/OPEN; #36/#37 downstream
  physical acceptance cannot be claimed. No OS root files changed.

## 2026-11-07 #35 one-shot bootstrap source pack, synthetic restore and no-go guard

- Existing Draft PR #39 reused; no privileged install, service restart, secret transfer or OS trust change. The authenticated mobile→Termux→strict-SSH→WSL path was usable; existing Worker-14 and Dashboard user services were active. Original installed controller/policy remain root:root mode 0555.
- Added a reproducible, nonprivileged Git-blob source pack `scripts/protected-update-bootstrap-pack.mjs` with exact clean HEAD, explicit source allowlist, owner-private staging, manifest SHA-256 and fail-closed nofollow/size/identity checks. The pack deliberately sets `installAuthorized:false`, includes no live signer keys/token and is **not an installation authorization**.
- Actual independent Codex security review found **P2**: a FIFO or oversized fake `MANIFEST.json` could hang/exhaust the package verifier. Fixed using O_NOFOLLOW|O_NONBLOCK, bounded fstat and regular-file checks before reading, plus synthetic FIFO/oversized regression tests.
- Implemented an **uninstalled** original-file migration/restore candidate: exact baseline hashes, backup before single-pointer switch and digest-checked wrapper replacement; refuse unsafe root permissions, symlinked originals, altered backup, crash leftovers and nonmatching rollback. Added fixed no-argument root entrypoint candidate, explicitly refuses the current source-only bundle and running from any mutable checkout.
- Three separate **synthetic** package→baseline→wrapper→original-restore integration runs and three deterministic source bundle builds are covered by tests, not live protected OS updates. All original bytes are compared after restore. Earlier actual WSL Node suite at code HEAD `c5277e0de8ecbc7d0fcd6f096ba1d5a56b265789` **280/280 PASS**, privacy check PASS. Full final-HEAD CI, complete independent privileged security audit and physical root tests are separately required.
- The real immutable root updater, reviewer/approval independent issuer operation and local protected signing keys, baseline pinning, least-privilege one-shot installation policy/undo and 2/2 physical protected updates remain incomplete. **One-time admin installation remains NO-GO; #35 OPEN.** Keep global `AI_WRITE=0` / `AI_PUSH=0`, main protection and existing data unchanged.

## 2026-11-07 #35 verified continuation — immutable roots and historical operation-ID recovery (NOT DEPLOYED)

- Reused existing Draft PR #39 and one isolated clean WSL worktree, with recovered authenticated ClosePaw/Termux/strict-SSH access. Current Worker and Dashboard user services both reported **active**. No root, service, credential, private-data, branch-protection or global `AI_WRITE=0` / `AI_PUSH=0` change.
- Added a candidate **real-root path-ancestry guard** checking fixed release and private journal directory chains for root ownership, directory type, no symlinks, and no group/other write. Wired it into authenticated read-only root preflight before credentials/OS release inspection. Synthetic negatives verify unsafe ancestors and journal modes; it is **not** an installed root entrypoint.
- Upgraded the **uninstalled** journal candidate to **v2** to persist trusted `previousCommit` with new `head`, rejecting v1 records rather than guessing. Removed external recovery calls' authority to supply the previous version identity.
- Actual independent Codex read-only security review on an intermediate source HEAD found **P2 historical result loss**: querying verified A→B after B→C, or earlier rollback after later success, was incorrectly refused. Fixed by a bounded, owner/mode-checked read-only journal history; enforces monotonic non-overlapping timestamps, linked previous/new commit+hashes, terminal predecessors and no active/stale history lock. Reconciliation distinguishes superseded completed records from uncertain successors; all outcomes remain `safeToReplay:false`.
- Regression cases cover serial A→B→C, rollback followed by retry, successor in unknown state, unjournaled pointer changes, broken hash ancestry, clock regression and stale locks. Actual Linux WSL Node suite **256/256 PASS**, privacy scanner PASS. Exact code-head [strict CI #42328998039](https://github.com/al-hub/mcp-dev-hub/actions/runs/42328998039) completed **SUCCESS**: `bootstrap` `npm run check`, **256 PASS, 0 FAIL**, privacy scan (139 files) PASS.
- Fresh **real independent Codex** review on code HEAD `9641f01768afa000029ef5c6819365f431281e3f` and exact main BASE `175ba1a481d9a55c0567402a2c905f457c7601e5`: **no actionable defects found within the expressly non-deployed candidate scope**. Reviewer ran 8 permitted read-only test files; actual WSL/CI separately ran all 256. This is **not** root privileged implementation security approval or formal GitHub APPROVED.
- Real read-only OS inventory: the proposed root-managed `versions`, `current`, independent trust config and durable root journal directories remain **absent**. Existing Worker/Dashboard remain active. Physical protected revisions **0/2**.
- **NO-GO for administrator installation:** still missing fully implemented immutable privileged updater, distinct operational independent reviewer/approval issuer signing keys and pinned root policy, one-shot original-file backup/installer/undo, full privileged security audit and physical acceptance. Keep PR #39 **Draft/OPEN**, Issue #35 OPEN, #36/#37 dependencies OPEN. No sudo request or overbroad policy.

## 2026-11-07 #35 read-only restart reconciliation (NOT DEPLOYED)

- Reused existing Draft PR #39; added `src/ops/protected-update-reconcile.mjs` and 9 synthetic tests. A root-owned supervisor may later use this **information-only** candidate to compare a durable operation-ID record with the active two-file release. An absent, pending, interrupted, unknown or inconsistent operation never authorizes replay, health promotion, switch or rollback. No privileged entrypoint was added.
- Source HEAD `9c2b20d9bafb1664d8366eb2f4c4c9118dbd2694` exact [CI #42320436322](https://github.com/al-hub/mcp-dev-hub/actions/runs/42320436322): completed **SUCCESS**, `bootstrap` job `npm run check` SUCCESS. New negative tests cover absent operation, prepared, switch-pending, switched-but-not-verified, durable verified/rollback, unknown, false terminal pointer and incorrect identity.
- Android ClosePaw v0.1.108 is responding, but the target private-network probe reported **target_unreachable**, Android VPN not present; actual strict-host-key SSH to WSL timed out (confirmed failure, not unknown write). No command replay, root change, service change or data operation occurred. Real operating acceptance and new live Codex review are **NOT VERIFIED** in this checkpoint.
- The immutable root updater, independent reviewer/approval signing principals and their protected provisioning, one-time migration/backup/installer, full privileged-code audit, two physical protected revisions, formal protected merge/main CI and #36/#37 real unattended E2Es remain missing. **Do not request administrator authorization or close #35** based on this source-only improvement. Maintain `AI_WRITE=0`, `AI_PUSH=0` and current services and policies.

## 2026-11-07 #35 protected-update candidate continuation (NOT DEPLOYED)

- Reused existing Draft PR #39 and the exact fixed two-file protected-update scope. No administrator rights, new trust policy, root installation, service restart, data reset, branch-protection change, or global AI_WRITE/AI_PUSH change.
- Added **read-only original installed pair capture** with exact legacy owner/mode/regular-file/nlink/size checks, no-follow and nonblocking access, inode consistency and SHA-256 evidence. This is **not** a deployed root backup, trust-issuer or updater.
- Actual independent read-only Codex review of prior candidate HEAD `cb63e95918e5f421143a2760e509572c7bd975e3` found a P2 release directory allowlist inconsistency. On the same PR branch, activation now rejects unexpected version entries before reusing/activating a release; regression tests cover refused staging/CAS and preserved current pointer.
- Source HEAD `2a6a93316d52673b2d9fbd1871c95c4b1759eae3`: authenticated WSL Node 24.15 run **222/222 PASS** and privacy scan **PASS** (manual staged-diff review still required). Exact-head strict GitHub [CI #42259651189](https://github.com/al-hub/mcp-dev-hub/actions/runs/42259651189) **SUCCESS**, `bootstrap` job `npm run check` SUCCESS.
- Fresh independent protected Codex CLI read-only review on this code HEAD and exact BASE `175ba1a481d9a55c0567402a2c905f457c7601e5`: **no actionable defects within the explicitly non-deployed candidate scope**. Reviewer ran 39 supported read-only tests; filesystem-mutating and child-process tests were constrained by its sandbox, separately covered by the real WSL/GitHub checks. This is not GitHub formal APPROVED or privileged installation acceptance.
- Operating read-only observation: legacy controller/policy root-owned, protected original version layout not migrated; Worker-14 and Dashboard both active. Existing main workspace was not changed; validation used a separate clean worktree.
- **NO-GO for the one-time admin action:** independent live review/approval signing principals and protected private-key provision, immutable root updater, original migration/rollback installer, minimum policy wiring and a separate full privileged-code independent audit remain missing. Physical updates **0/2**, broad Issue-development E2Es **0/3**. Keep PR #39 Draft and Issues #35/#36/#37 OPEN. Never infer root authority from candidate CI.

---
## 2026-11-06 #35 — One-time bootstrap readiness inventory (no deployment)

- Rechecked AGENTS.md, SECURITY.md, the current ops constraints, and Issues
  #35, #36 and #37. A single bounded administrator bootstrap is preferred
  to repeated sudo prompts, but it must not be spent on incomplete code.
- A new authenticated read-only mobile→Termux→SSH→WSL probe returned Linux /
  exit 0. Existing protected controller/policy/AGY/Codex components were
  present, with both Worker and Dashboard user services running. Protected
  root directory is root-owned and non-group/other-writable.
- Fixed-version `versions` migration and the proposed protected evidence trust
  directory were absent. A bounded system-local executable inventory did not
  find a preinstalled protected updater. This is *not* a complete OS permission
  audit; existing narrow launcher privilege must be checked before a new rule.
- Wrote the scope/admission/rollback decision and no-repeat-sudo acceptance
  gates in [docs/PROTECTED_UPDATE_ONE_SHOT_BOOTSTRAP.md](PROTECTED_UPDATE_ONE_SHOT_BOOTSTRAP.md).
  For new root policy, issuer keys or updater code, require a separate explicit
  authorization **before** starting a job, not a surprise mid-run prompt.
- [CI #42219429483](https://github.com/al-hub/mcp-dev-hub/actions/runs/42219429483)
  succeeded for the new document-only scope commit. The previous independent
  Codex review covers only the older uninstalled candidate code, not an
  installed, independently audited root updater.
- **Still NO-GO for administrator action:** separately trusted live issuers,
  complete immutable root updater, reviewed migration/backup/rollback installer
  and physical unattended updates 0/2 remain missing. Do not claim #35 complete
  or proceed to #36/#37 acceptance. No credentials or protected files changed.

## 2026-11-06 #35 — Root current-release and request preflight (candidate only)

- Added `inspectProtectedCurrentSnapshot` to derive the exact previous
  controller pair hashes from the protected current version, rejecting
  unexpected files, unsafe modes and no-follow violations. No previous hashes
  are trusted solely from Worker input.
- Added bounded canonical `parseProtectedUpdateRequest` with an exact
  non-executable allowlist. Worker-supplied root paths, commands, trust keys,
  credentials, privileges and policy updates are forbidden.
- Added `preflightRootProtectedUpdateRequest`: fixed root-side read-only
  composition of authenticated GitHub/review evidence, actual installed
  release metadata and verified source bytes. Returns only bounded status;
  deliberately has **no** privileged install/switch/retry entrypoint.
- The first synthetic CI detected an internal missing owner argument in one
  CAS pointer check; corrected before acceptance. Exact candidate
  [CI #42211771953](https://github.com/al-hub/mcp-dev-hub/actions/runs/42211771953)
  passed. Independent protected Codex read-only review on its exact SHA
  returned no actionable defects within candidate scope. Reviewer could
  not execute wrapper subprocess tests in its sandbox; CI covered them.
- No root bootstrap was attempted. Missing: separately trusted reviewer and
  approval signing issuers/private key protection, reviewed installed
  immutable root updater, narrow administrator bootstrap, physical 2/2
  unattended protected updates and rollback/unknown E2E, formal GitHub
  APPROVED, protected merge/main CI. #35/#36/#37 remain OPEN.
- Preserve old root-controlled files, operational services, private state,
  branch protection and globally `AI_WRITE=0`, `AI_PUSH=0`.


## 2026-11-06 #35 — Authenticated evidence candidate (2026-11-06)

- Existing Draft PR #39 reused. Candidate fixed HTTPS GitHub API reader now
  validates the exact PR HEAD/BASE, required workflow ID/path, successful
  required bootstrap job, strict branch protection, and associated CI run's
  exact tested HEAD and BASE.
- Added canonical short-lived independent Codex **signed** review evidence
  with a reviewer signing principal distinct from the updater approval
  principal. Root-side read-only preflight loads the two pinned public keys
  and GitHub credential exclusively from a fixed root-owned directory;
  it never accepts arbitrary Worker-supplied key paths or network URLs.
- Candidate controller/policy bytes are fetched only from two fixed GitHub
  content paths at the approved immutable commit and SHA-256/size verified.
- An independent Codex review found two defects: unrelated/stale-base CI
  acceptance and rollback-restage conflict. Both were fixed; new tests
  verify stale CI base refusal, exact immutable release reuse after rollback,
  and early block of damaged existing versions.
- [Strict CI #42209694816](https://github.com/al-hub/mcp-dev-hub/actions/runs/42209694816)
  completed SUCCESS for the revised source and tests. A **new final-HEAD
  independent Codex review** is required after the documentation update.
- **Not deployed:** No root-owned immutable verified updater entrypoint,
  independent private signer/review attestor or installed root trust
  configuration. Noninteractive sudo cannot be assumed. No actual
  privileged A→B→C revisions or reboot/disconnect recovery evidence.
- #35/#36/#37 remain OPEN. Keep `AI_WRITE=0`, `AI_PUSH=0` globally and
  branch protection, Worker/Dashboard and private data unchanged.


## 2026-11-06 #35 candidate protected release chain — CODE ONLY

- Existing Draft PR #39 reused; introduced signed approval + persistent journal
  integration, staged fixed two-file versions, one atomic CAS release pointer,
  compare-and-swap rollback, and a fixed controller wrapper candidate matching
  the legacy controller's direct-invocation guard.
- Exact code/tests CI: [run #42204022313](https://github.com/al-hub/mcp-dev-hub/actions/runs/42204022313)
  SUCCESS for synthetic two consecutive updates, rollback on confirmed
  negative health, and unknown-never-replay. Additional wrapper/docs candidate
  [run #42204648331](https://github.com/al-hub/mcp-dev-hub/actions/runs/42204648331)
  SUCCESS; code was not installed under root.
- Physical read-only noninteractive sudo check returned password required.
  No broad authority, protected files, root service, branch protections or
  live Worker/Dashboard were modified.
- **Critical pending trust gate**: the frozen proof used in candidate
  transaction tests is NOT an authenticated independent GitHub/CI/Codex
  attestation. A separately reviewed immutable root verifier and independent
  signer/key bootstrap are required before installing any privileged entrypoint.
  See docs/PROTECTED_UPDATE_BOOTSTRAP.md.
- Missing: final-HEAD independent Codex review of the new candidate, root
  authorization and install, two genuine unattended protected source updates,
  failure/disconnect physical acceptance, PR/main CI after protected merge,
  and #35 CLOSED. Dependent #36/#37 remain OPEN. AI_WRITE=0/AI_PUSH=0 globally.


## 2026-11-04 #10 reviewer-app preflight

- Added a separately invoked, bounded GitHub App connection preflight using the existing scoped App client. Checks expected App bot identity, exact PR HEAD, PR author/base/state. No APPROVE endpoint and no background automation are exposed.
- Uses only externally configured App identity, installation ID, protected key file reference and exact expected HEAD. Without these, preflight returns BLOCKED without reading a key. No credentials are committed.
- Initial real execution is BLOCKED: required App runtime configuration was not provisioned in this execution context. Successful synthetic client tests do not establish a real GitHub App JWT or installation token exchange.
- Independent authenticated full-PR Codex PASS, verified acceptance evidence, legitimate GitHub review, current-head CI, production acceptance and issue close remain pending. Preserve production configuration and branch protection.

The original Stage 0 snapshot below is historical and does not describe the current #10 implementation state.

---

## Implemented

- Public repository scaffold and provider-neutral AI contributor instructions.
- Disabled synthetic target configuration, runtime shape validation and target/workspace selection.
- Executor and durable job interfaces (contracts only).
- Privacy candidate scanner with regression tests and GitHub CI definition.

## Not implemented

MCP runtime/SDK, actual file or command tools, SSH, durable storage, authentication, tunnels, CLI adapters, installer and service startup.

## Next work

Stage 1: introduce a pinned official SDK and lockfile, implement stdio handshake and one harmless tool, then workspace-scoped file operations and controlled local execution with tests.
Keep all real configuration outside the repository. Read AGENTS.md first.

## Validation

Local Node.js 24 validation: 7 tests passed; privacy candidate check passed for all staged source files. Remote CI results must be checked separately after push. No real device or client acceptance is claimed.
