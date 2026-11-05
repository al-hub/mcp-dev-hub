# Current constraints register — MCP Dev Hub

> **Public, sanitized operational snapshot.** Initial verification: **2026-11-06 (Asia/Seoul)**. Applies to preparation issues [#35](https://github.com/al-hub/mcp-dev-hub/issues/35) → [#36](https://github.com/al-hub/mcp-dev-hub/issues/36) → [#37](https://github.com/al-hub/mcp-dev-hub/issues/37).
>
> This file is the **single current-constraints index**, not proof of unrestricted command privileges, an authorization policy, or a replacement for operational acceptance evidence. Development progress/history remains in [docs/STATUS.md](../STATUS.md). Public content must follow [SECURITY.md](../../SECURITY.md) and [AGENTS.md](../../AGENTS.md).

## How to use and update

1. **Read this file before environment-dependent work.** Reuse verified findings instead of repeating a full environment/code audit. Do a **narrow, read-only recheck** when an entry is stale, affected by a deployment, contradictory, or required for an irreversible operation.
2. Treat **observed** (direct result), **blocked** (confirmed refusal), and **unverified** (not established) differently. A reachable MCP endpoint does not prove downstream WSL command execution; CI success does not prove device deployment.
3. When a constraint changes, update its **status, last verified date, narrow evidence, impact, and release condition**. Retain superseded results in the change log with evidence; do not silently discard negative findings.
4. Link affected issues/PRs to this canonical file; avoid copying divergent status paragraphs into multiple issue bodies. Do not publish private hostnames, usernames, IPs, home/workspace absolute paths, authentication material, command output, or runtime state.
5. Respect all permission boundaries. No generic shell or root privileges are inferred from read-only connectivity. Never rerun an uncertain or rejected remote command as a guess.

## Active constraints — last checked 2026-11-06 KST

| ID | Status and last verification | Directly observed / bounded claim | Effect on work | Release / recheck condition |
| --- | --- | --- | --- | --- |
| **C-01 Microduck workspace boundary** | **BLOCKED for Dev Hub Git operations via Microduck**, 2026-11-06 | A read-only command executed inside WSL2 through Microduck. The Dev Hub checkout exists, but a Git command with that checkout as the command working directory was rejected because it is **outside the Microduck workspace**. | Microduck is **not currently a general-purpose Dev Hub executor**. GitHub API operations and CI remain separate paths. | Authorized, narrowly scoped Dev Hub execution path is demonstrably available; verify a harmless repository-scoped command without loosening global permissions. |
| **C-02 independent reviewer / coding CLI path** | **UNVERIFIED for actual execution**, 2026-11-06 | `codex` and `agy` were **not on the Microduck command PATH**. Executable files were observed under an existing root-owned protected tool directory, but were **not invoked**. | A real final-HEAD independent Codex review (or AGY execution) cannot be claimed through the tested Microduck route. This does **not** prove the tools are absent from all WSL execution contexts. | Verify exact executable, permitted launcher, isolation, exit code, and final HEAD/BASE bound review evidence in an authorized WSL session. |
| **C-03 protected updater authority** | **BLOCKED for direct non-root write; expected security boundary**, 2026-11-06 | The protected tool directory is root-owned and not writable by the current ordinary WSL user. No privileged install or replacement attempted. | The #35 authenticated, allowlisted updater and atomic rollback still require implementation and physical operational proof. **Do not fix by broadening directory permissions or granting arbitrary sudo.** | Prove approved vA→vB installation, ownership/hash verification, rollback, rejection cases, and zero per-issue sudo prompts using a trusted installer; a narrowly scoped initial bootstrap may require explicit approval. |
| **C-04 ClosePaw alternate route** | **BLOCKED for Bridge→WSL command execution**, 2026-11-06 | ClosePaw app v0.1.107 responded, but passive Bridge health was unavailable, authenticated jobs were not ready, Termux RUN_COMMAND support was reported unavailable, and maintenance status returned HTTP 404. WSL command completion through this route was **not verified**. | This is an optional remote-access route, **not** a mandatory dependency for #35 code work. Do not claim app reachability = Bridge recovery. | Confirm new daemon/app deployed on actual device, successful admission of one **new harmless** command, exit 0/result retrieval, preservation/dedup evidence, and Bridge→WSL end-to-end. See [ClosePaw #225](https://github.com/al-hub/closepaw/issues/225). |
| **C-05 #35→#37 acceptance gates** | **OPEN / NOT ACCEPTED**, 2026-11-06 | #35's [PR #38](https://github.com/al-hub/mcp-dev-hub/pull/38) and [PR #39](https://github.com/al-hub/mcp-dev-hub/pull/39) contain preparatory manifest/approval/journal logic; they do **not** establish a production root-owned updater or successful independent final-head review and WSL acceptance. #36 and #37 remain open. | Do not report a working unattended production-development pipeline or close these issues from synthetic checks alone. | Complete #35 root updater + security/CI/operational gates, then #36 generic Issue→AI→CI→merge→close, then #37 three independent zero-intervention end-to-end runs. |

## Architecture and sequencing

- **Execution target:** WSL Worker / protected executors. **Control entry:** Microduck MCP or ClosePaw MCP are alternative transport routes; neither is the unattended Worker itself.
- **Prefer the working authorized route.** Continue #35's code/CI work through GitHub even when ClosePaw is blocked. Check actual privileges and independent-review availability before claiming #35 operational completion.
- **#35 → #36 → #37** is the acceptance sequence. ClosePaw #225 is tracked independently. Do not convert a single transport failure into a global prerequisite for all Dev Hub development.
- A status check is not permission to install, alter root-owned policy, replay commands, bypass reviews, or enable `AI_WRITE`/`AI_PUSH` globally.

## Change log

| Date (KST) | Change | Evidence |
| --- | --- | --- |
| 2026-11-06 | Initial sanitized constraints snapshot from read-only Microduck and ClosePaw checks. No local files, running services, user data, or security settings were changed by those checks. | [Dev Hub #35](https://github.com/al-hub/mcp-dev-hub/issues/35), [ClosePaw #225](https://github.com/al-hub/closepaw/issues/225) |
| 2026-11-06 | ClosePaw [PR #226](https://github.com/al-hub/closepaw/pull/226) is reported merged in #225, but that is **distinct from deployed-device Bridge/WSL acceptance**. Retain C-04 until physical proof. | [ClosePaw #225](https://github.com/al-hub/closepaw/issues/225) |
