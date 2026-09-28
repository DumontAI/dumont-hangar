# Hangar MCP changelog

## 0.2.0 — HGR-6: role-gated writes (not deployed yet)

### Changes

- New write tools `hangar_create_work_item`, `hangar_update_work_item`,
  `hangar_add_comment` (no delete). Read tools unchanged.
- Per-tool roles: read tools accept `hangar_reader` or `hangar_writer`; write
  tools need `hangar_writer` and answer a `FORBIDDEN` tool error otherwise.
- New config: `HANGAR_WRITE_PROJECTS` (subset of `HANGAR_ALLOWED_PROJECTS`;
  empty disables writes), `HANGAR_WRITE_RATE_LIMIT` (default 20/min/user),
  `MCP_OIDC_READER_ROLE`, `MCP_OIDC_WRITER_ROLE`, `MCP_OIDC_USERINFO_URL`.
  `MCP_OIDC_REQUIRED_ROLE` is still honored as the reader role.
- Metadata `scopes_supported` and the 401/403 challenge now advertise
  `openid email` plus both role scopes; none is required on the token.
- Caller email for attribution and `"me"`: token `email` claim, else a lazy,
  cached userinfo lookup with the caller's bearer (writes only); falls back to
  the token `sub` on any failure.
- Write input with credential-looking text is refused (`SECRET_DETECTED`);
  descriptions and comments get a `— via MCP por <email|sub>` footer.
- One JSON audit line per tool call on stderr (journald).
- CI on GitHub-hosted runners (the repo is public) and a gated self-hosted
  deploy job (`.github/workflows/hangar-mcp.yml`, `scripts/deploy-mcp-hel1.sh`)
  that manages `/etc/dumont-hangar-mcp.env` from GitHub environment values.
  Until that is set up, deploy by hand: README → "Manual deploy".

### Owner steps for the manual deploy (first release)

1. **ZITADEL** — in project `ZITADEL DCR` (`390213468206137347`) create the
   role `hangar_writer`, then add it to the user grants of the people who may
   write (keep `hangar_reader` for everyone else).
2. **Hangar** — confirm the bot `hangar-mcp@dumont.au` is a **Member** (role 15
   or higher, not Guest) of every project that will go in
   `HANGAR_WRITE_PROJECTS`; otherwise writes fail with `UPSTREAM_FORBIDDEN`.
   Assignees must also be project Members, or Plane drops them silently.
3. **Deploy by hand** following README → "Manual deploy": the existing
   `/etc/dumont-hangar-mcp.env` stays; append `HANGAR_WRITE_PROJECTS=""`,
   `HANGAR_WRITE_RATE_LIMIT="20"`, `MCP_OIDC_WRITER_ROLE="hangar_writer"`.
   Check the loopback 401, the challenge/metadata scopes and the journal.
4. **Enable writes** — set `HANGAR_WRITE_PROJECTS="HGR"` (same spelling as in
   `HANGAR_ALLOWED_PROJECTS`) and restart the service.
5. **Clients** — everyone who got `hangar_writer` re-authenticates so the new
   token carries it and the `openid email` scopes: Claude Code `/mcp` → Hangar
   → re-authenticate; dumont-code: expire/remove the stored Hangar token.
6. **Verify** — `journalctl -u dumont-hangar-mcp -o cat | grep hangar.mcp.tool`
   shows one line per call; a first write in `HGR` shows the footer with an
   email (a `sub` there means the userinfo lookup found no email; look for
   `hangar-mcp userinfo-email outcome=` in the journal).

### Later: the deploy workflow

1. **GitHub `production` environment** — create the variables and secrets
   listed in README → "Deploy workflow", copying the current values from
   `/etc/dumont-hangar-mcp.env` (key names in the README; never paste values
   in chat). Require reviewers on the environment and protect `dumont`.
2. **Runner** — add the label `hangar-mcp` to the self-hosted runner on
   airbase-hel1, or set the repository variable `HANGAR_MCP_DEPLOY_RUNS_ON` to
   `["self-hosted","linux","x64","bugit-mcp"]`. CI does not need it (it runs on
   `ubuntu-latest`). The runner user needs `sudo` for `install`, `test`, `sed`,
   `systemctl`, `journalctl`.
3. **Deploy** — Actions → "Hangar MCP CI/CD" → Run workflow on `dumont` with
   `deploy=true`, `confirmation=DEPLOY_HANGAR_MCP`. If the script lists env
   keys it would drop, map them to `HANGAR_MCP_*` values or, after checking,
   set `HANGAR_MCP_ALLOW_ENV_KEY_DROP=true` for that run.

Optional: a ZITADEL service user with `hangar_reader` only plus client
credentials enables the authenticated read smoke
(`HANGAR_MCP_OIDC_SMOKE=true`, `HANGAR_MCP_OIDC_SMOKE_CLIENT_ID/SECRET`).
