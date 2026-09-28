# Hangar MCP changelog

## 0.2.0 — HGR-6: role-gated writes (not deployed yet)

### Changes

- New write tools `hangar_create_work_item`, `hangar_update_work_item`,
  `hangar_add_comment` (no delete). Read tools unchanged.
- Per-tool roles: read tools accept `hangar_reader` or `hangar_writer`; write
  tools need `hangar_writer` and answer a `FORBIDDEN` tool error otherwise.
- New config: `HANGAR_WRITE_PROJECTS` (subset of `HANGAR_ALLOWED_PROJECTS`;
  empty disables writes), `HANGAR_WRITE_RATE_LIMIT` (default 20/min/user),
  `MCP_OIDC_READER_ROLE`, `MCP_OIDC_WRITER_ROLE`. `MCP_OIDC_REQUIRED_ROLE` is
  still honored as the reader role.
- Metadata `scopes_supported` and the 401 challenge now list both role scopes.
- Write input with credential-looking text is refused (`SECRET_DETECTED`);
  descriptions and comments get a `— via MCP por <email|sub>` footer.
- One JSON audit line per tool call on stderr (journald).
- CI and a gated deploy workflow (`.github/workflows/hangar-mcp.yml`,
  `scripts/deploy-mcp-hel1.sh`). The deploy script now manages
  `/etc/dumont-hangar-mcp.env` from GitHub environment values.

### Owner steps before the first deploy (in order)

1. **ZITADEL** — in project `ZITADEL DCR` (`390213468206137347`) create the
   role `hangar_writer`, then add it to the user grants of the people who may
   write (keep `hangar_reader` for everyone else).
2. **Hangar** — confirm the bot `hangar-mcp@dumont.au` is a **Member** (role 15
   or higher, not Guest) of every project that will go in
   `HANGAR_WRITE_PROJECTS`; otherwise writes fail with `UPSTREAM_FORBIDDEN`.
   Assignees must also be project Members, or Plane drops them silently.
3. **GitHub `production` environment** — create the variables and secrets
   listed in `README.md` → "Deploy workflow". Copy the current values from
   `/etc/dumont-hangar-mcp.env` on airbase-hel1 (at least
   `HANGAR_MCP_API_KEY`, `HANGAR_MCP_WORKSPACE_SLUG`,
   `HANGAR_MCP_ALLOWED_PROJECTS`, `HANGAR_MCP_ALLOWED_HOSTS`,
   `HANGAR_MCP_RESOURCE_URL`, `HANGAR_MCP_OIDC_ISSUER`,
   `HANGAR_MCP_OIDC_JWKS_URL`, `HANGAR_MCP_OIDC_AUDIENCE`, and the
   introspection ones if used). Start with `HANGAR_MCP_WRITE_PROJECTS` empty
   to ship the code with writes off, then set it (e.g. `HGR`) and redeploy.
4. **Runner** — add the label `hangar-mcp` to the self-hosted runner on
   airbase-hel1, or set the repository variables `HANGAR_MCP_CI_RUNS_ON` /
   `HANGAR_MCP_DEPLOY_RUNS_ON` to `["self-hosted","linux","x64","bugit-mcp"]`
   to reuse the Bugit MCP runner. The runner user needs `sudo` for `install`,
   `test`, `sed`, `systemctl`, `journalctl`.
5. **Deploy** — Actions → "Hangar MCP CI/CD" → Run workflow on `dumont` with
   `deploy=true`, `confirmation=DEPLOY_HANGAR_MCP`. If the script lists env
   keys it would drop, map them to `HANGAR_MCP_*` values or, after checking,
   set `HANGAR_MCP_ALLOW_ENV_KEY_DROP=true` for that run.
6. **Clients** — everyone who got `hangar_writer` re-authenticates so the new
   token carries it: Claude Code `/mcp` → Hangar → re-authenticate;
   dumont-code: expire/remove the stored Hangar token. `"me"` as assignee also
   needs the client to request the `email` scope.
7. **Verify** — `journalctl -u dumont-hangar-mcp -o cat | grep hangar.mcp.tool`
   shows one line per call; a first write in `HGR` shows the footer.

Optional: a ZITADEL service user with `hangar_reader` only plus client
credentials enables the authenticated read smoke
(`HANGAR_MCP_OIDC_SMOKE=true`, `HANGAR_MCP_OIDC_SMOKE_CLIENT_ID/SECRET`).
