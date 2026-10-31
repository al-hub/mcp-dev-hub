# Roadmap and acceptance gates

| Stage | Deliverable | Acceptance |
| --- | --- | --- |
| 0 | Public bootstrap | shared AI instructions, synthetic config, validation tests, privacy check, CI |
| 1 | Local MCP/executor | stdio SDK handshake, scoped read/patch, controlled process start, exit/log/cancel, path escape tests |
| 2 | SSH executor | synthetic SSH fixture, same operations remotely, host key and disconnect tests, no local fallback |
| 3 | Durable jobs | private SQLite/logs, idempotency, workspace locking, restart reconciliation, cancel |
| 4 | Remote access | authenticated HTTPS Streamable HTTP, origin checks, tested client compatibility matrix |
| 5 | Coding CLI | one adapter, edit/test loop, status/diff/result recovery after chat disconnect |
| 6 | Operations | autostart, connection recovery, retention/redaction, setup guide, release packaging |

Final scenario: a mobile AI client starts a code fix and tests on a configured remote workspace, disconnects, then retrieves the same job's status, tests and diff. Do not call this complete before actual acceptance.
