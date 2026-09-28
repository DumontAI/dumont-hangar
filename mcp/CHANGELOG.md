# Hangar MCP changelog

## 0.2.0 — HGR-6: role-gated writes (not deployed yet)

### Changes

- New write tools `hangar_create_work_item`, `hangar_update_work_item`,
  `hangar_add_comment` (no delete). They are registered only when
  `HANGAR_WRITE_PROJECTS` is set. Read tools unchanged, except that their
  descriptions now say read text is redacted/truncated and must not be written
  back.
- Update never replaces a description: `append_description` appends text and a
  footer after the raw stored description (fetched server-side, never
  returned).
- Per-tool roles: read tools accept `hangar_reader` or `hangar_writer`; write
  tools need `hangar_writer` and answer a `FORBIDDEN` tool error otherwise.
  `my:zitadel:grants` counts only as the exact `<audience>:<role>` entry.
- New config: `HANGAR_WRITE_PROJECTS` (subset of `HANGAR_ALLOWED_PROJECTS`;
  empty disables writes), `HANGAR_WRITE_RATE_LIMIT` (default 20/min/user),
  `MCP_OIDC_READER_ROLE`, `MCP_OIDC_WRITER_ROLE`, `MCP_OIDC_USERINFO_URL`.
  `MCP_OIDC_REQUIRED_ROLE` is still honored as the reader role.
- Metadata `scopes_supported` and the 401/403 challenge advertise
  `openid email` plus both role scopes; none is required on the token.
- Caller email for attribution and `"me"`: token `email` claim with
  `email_verified === true`, else a lazy, cached userinfo lookup (writes only,
  same verified rule, no `preferred_username`); falls back to the token `sub`.
- Credential-looking input is refused (`SECRET_DETECTED`) with value-shaped
  rules that let ordinary PT-BR/EN prose about tokens and passwords through.
  Footer-shaped lines are stripped from caller text (no stacking, no forgery).
- One JSON audit line per tool call on stderr (journald).
- CI only (`.github/workflows/hangar-mcp.yml`, GitHub-hosted `ubuntu-latest`).
  The repository is public, so there is no deploy job; deploy is manual
  (README → "Manual deploy").

### Owner steps for the manual deploy (first release)

1. **ZITADEL** — in project `ZITADEL DCR` (`390213468206137347`) create the
   role `hangar_writer`, then add it to the user grants of the people who may
   write (keep `hangar_reader` for everyone else). Make sure no other ZITADEL
   project defines roles named `hangar_reader` or `hangar_writer`.
2. **Hangar** — confirm the bot `hangar-mcp@dumont.au` is a **Member** (role 15
   or higher, not Guest) of every project that will go in
   `HANGAR_WRITE_PROJECTS`; otherwise writes fail with `UPSTREAM_FORBIDDEN`.
   Assignees must also be project Members, or Plane drops them silently.
3. **Deploy by hand** following README → "Manual deploy": the existing
   `/etc/dumont-hangar-mcp.env` stays; append `HANGAR_WRITE_PROJECTS=""`,
   `HANGAR_WRITE_RATE_LIMIT="20"`, `MCP_OIDC_WRITER_ROLE="hangar_writer"`.
   Validate with `systemd-run` before switching; then check the loopback 401,
   the challenge/metadata scopes and the journal.
4. **Enable writes** — set `HANGAR_WRITE_PROJECTS="HGR"` (same spelling as in
   `HANGAR_ALLOWED_PROJECTS`) and restart the service. `tools/list` then shows
   12 tools instead of 9.
5. **Clients** — everyone who got `hangar_writer` re-authenticates so the new
   token carries it and the `openid email` scopes: Claude Code `/mcp` → Hangar
   → re-authenticate; dumont-code: expire/remove the stored Hangar token.
6. **Verify** — `journalctl -u dumont-hangar-mcp -o cat | grep hangar.mcp.tool`
   shows one line per call; a first write in `HGR` shows the footer with an
   email (a `sub` there means no verified email was found; look for
   `hangar-mcp userinfo-email outcome=` in the journal).

Later ticket: an automated deploy driven from a private repository (not from
this public one).
