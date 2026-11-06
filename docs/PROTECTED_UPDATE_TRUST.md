# Issue #35 — unattended protected-file update trust boundary

## Confirmed baseline (2026-11-05)

The production Worker and Dashboard are active. Executable and policy files inside the protected installation directory are owned by root and not writable by the Worker identity. Existing noninteractive `sudo` permission is unavailable. Development flags are disabled globally. A user-owned checkout or Worker process **cannot safely replace protected files** without an additional OS privilege boundary.

The protected-file update problem is separate from GitHub Issue orchestration: completing a single permitted AI canary does not imply that arbitrary Issue code may update trusted executables.

## Non-negotiable properties

1. Untrusted Issue text, model answers, repository checkout, generated code and a user-writable staging folder are **data only**. They must never become a root-executed script or authorize a privileged update.
2. The protected updater itself, trust roots, policy and executable ancestry remain root-owned and non-writable by Worker identity. No general `NOPASSWD: ALL`, writable protected directory, setuid shell, or unrestricted argument list.
3. An update requires an independently verified, exact upstream protected commit plus authentic CI result, independent reviewed HEAD/BASE evidence and a separately authorized file policy. Validation of a proposed manifest **does not authenticate any of those facts**.
4. Update scope is the exact reviewed `controller-pair` (two controller/policy files), with constant destination paths, bounded regular-file size, safe file descriptors, SHA-256 verification, correct ownership/mode, atomic staging and a known-good rollback. Binary updates (`agy`/`codex`) require a **separate policy**, not a widened manifest.
5. The root boundary may install bounded files but must not run untrusted contents as root. Any user-level executable that consumes GitHub or model credentials is admitted only after its own integrity and review checks.
6. A durable operation ID and lock must distinguish prepared, applied, verified, rolled back and **unknown** states. Losing the connection must never cause a blind replay of a privileged write.
7. After an installed change, verify the Worker/Dashboard health, exact installed hashes, retained data and unchanged branch protection/disabled global AI flags.

## Narrow sequential implementation

- **Gate A (this PR)**: test the untrusted manifest parser. The two-file policy rejects paths, commands, extra fields, malformed hashes, partial bundles, size violations and mismatched verified commit. All tests run without privileges. No updater is installed.
- **Gate B**: implement a separately authenticated root-owned updater with fixed destinations, authenticated evidence retrieval, bounded FS operations, lock/atomic rollback and a read-only preview. Demonstrate that a compromised checkout or an arbitrary Issue cannot influence privileged arguments.
- **Gate C**: independently audit the complete dependency chain, PR CI, restart/rollback/negative tests. If a root-only installer must be bootstrapped, obtain **one explicit local OS authorization** and never ask for the password in chat.
- **Gate D**: perform two genuinely independent trusted-file revisions through the approved unprivileged request path, with **zero repeated sudo prompts**, verify hashes/rollback and service health, and record audited evidence. Only then close #35.

A GitHub merge or a green parser test does not demonstrate Gate B–D.

## Trust status

The current change introduces no privilege grant, sudoers/systemd service rule, root write, background monitor, new account, GitHub App or remote endpoint. Do not activate any such facility until its security review and narrowly scoped installation are complete.

Follow-up: #36 generic unattended Issue development; #37 independent E2E acceptance. Neither issue is considered complete on the basis of #35 Gate A alone.
