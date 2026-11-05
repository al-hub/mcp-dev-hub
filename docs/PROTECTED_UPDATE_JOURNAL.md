# #35 updater journal preview — NOT a privileged updater

The source module `src/ops/protected-update-journal.mjs` is a **pure,
non-I/O transition guard**. It models one fixed two-file update with
a durable operation ID, BASE/HEAD, old/new SHA-256 hashes and phases:

`prepared → switch_pending → switched → verified`, or a bounded
rollback/aborted/unknown terminal state.

The trusted installer must persist each state with fsync and atomic
replacement **before** any filesystem switch/rollback. A lost response
cannot authorize resubmission: `unknown` remains terminal until an
independently designed root-owned reconcile/readback protocol exists.
Neither caller-supplied observed hash strings nor a health boolean prove
filesystem ownership, atomicity, correct key, actual GitHub CI or Codex
review. Only the future independently trusted root-side verifier may supply
them from OS and authenticated GitHub observations.

This work does **not** implement an installer, root service,
authoritative provenance, lock, disk journal, physical readback,
atomic whole-bundle switch, or an authorized retry. Tests verify only
the pure transition rules. Gate B-D of #35 stay OPEN.
