# #35 Gate B groundwork — signed approval guard (not an updater)

This stacked work adds an **inert, read-only Ed25519 signature verifier**
for a signed, canonical JSON *approval* binding the precise two-file
manifest digest, repository, HEAD, BASE, CI run ID and HEAD, independent
review digest/HEAD/BASE/verdict, durable operation ID, and short expiry.

**Not production authorization:** The signature checker cannot authenticate
GitHub CI, verify that a Codex review is independent, check branch protection,
prove the signature issuer was authorized, prevent replays without a durable
journal, stage/replace root files, or roll back. Those checks MUST occur in a
separately installed trusted root-owned component. The trusted key and
expected values must be loaded from root-owned state or authenticated
authoritative queries, NEVER a PR, Issue, untrusted manifest or Worker env.

No root service, sudoers, daemon, privileged command, settings change or
secret is introduced by this change. This work must not be merged/deployed
without final-head independent Codex security audit. PR #38 Gate A remains
unchanged and independently reviewable.

Still missing for #35 acceptance: authentic root-side independent proof
retrieval; root-owned updater bootstrap; fixed-allowlist no-follow FD-based
staging, ownership/hash/atomic rollback; durable single-operation journal;
service/data preservation; on-device tests; two successful unattended
updates. None is evidenced by green CI on this branch.
