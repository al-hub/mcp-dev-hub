# MCP layer (planned)

Use the official MCP SDK; pin the selected SDK version and commit the lockfile when introduced.
Begin with stdio for local integration tests, then authenticated Streamable HTTP for remote clients.
Tools: targets_list, workspace_read, workspace_patch, job_start, job_status, job_logs, job_cancel.
Return aliases and relative paths by default, never raw private configuration. Authorize every request.
No network listener or tool registration exists yet.
