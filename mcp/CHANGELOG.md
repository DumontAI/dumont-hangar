# Hangar MCP changelog

## 0.3.0 — the MCP acts as the logged-in user (not deployed yet)

Needs the Hangar (Plane fork) side first: API v1 accepting
`Authorization: Bearer <ZITADEL JWT>` (`apps/api/plane/dumont/`,
`DUMONT_API_BEARER_ENABLED=1`, `DUMONT_API_AUDIENCES` containing
`MCP_OIDC_AUDIENCE`) and RFC 7662 introspection of opaque tokens
(`DUMONT_API_INTROSPECTION_*` configured). Without the Hangar introspection,
users of dynamically registered clients (opaque tokens: Codex, OpenCode) get
an error from Hangar on every tool call.

### Changes

- Upstream calls to Hangar API v1 send the caller's own verified access token
  (`Authorization: Bearer`), never an `x-api-key`. Hangar applies the user's
  own workspace/project permissions and records the user as the author. The
  bot account `hangar-mcp@dumont.au` is no longer used.
- Only a token that passed this server's validation is forwarded, verbatim:
  a locally verified RS256 JWS, or an opaque (JWE) token that introspection
  reported active and that passed the same claims policy (issuer, audience,
  org-bound role, access-token type). ID tokens, other audiences, inactive or
  failed introspection are rejected by this server and never reach Hangar.
  `TOKEN_NOT_FORWARDABLE` remains only as a defensive guard (no validated
  token on the request).
- Per request, the HTTP layer builds a new McpServer and a Hangar client bound
  to the verified caller; no global mutable caller state.
- Caches (project list, workspace members, Hangar user id) are keyed per token
  `sub`, bounded (1000 users, LRU) and never shared between users.
- Pagination cursors: HMAC key from the new required `MCP_CURSOR_SECRET`
  (>= 32 bytes; previously derived from the API key), and bound to the
  caller's `sub`.
- `"me"` is the Hangar user behind the token (`GET /api/v1/users/me/`). The
  userinfo email lookup and `MCP_OIDC_USERINFO_URL` are removed; the
  principal no longer carries an email.
- Footer is now `— via MCP` (no name). Footer-shaped lines of both the new and
  the old `— via MCP por <name>` shape are stripped from caller text.
- Hangar errors mapped to actionable tool errors: `ACCOUNT_NOT_LINKED` (sign
  in once to Hangar web with Dumont login), `WRITER_ROLE_REQUIRED`,
  `PROJECT_ACCESS_DENIED` (names the `hangar.project.<id>.member` role),
  `TOKEN_EXPIRED` (not retryable with the same token), `UPSTREAM_UNAUTHORIZED`.
  A Hangar 401 never becomes an MCP HTTP 401.
- An access token with 30 s or less left (JWT `exp`, or the introspection
  `exp` for an opaque token) is refused by the authorizer with
  the regular HTTP 401 challenge, so clients refresh before the token is
  forwarded; `TOKEN_EXPIRED` only remains for calls that outlive that margin.
- Footer anti-forgery compares a folded form of each line: zero-width
  characters removed, any Unicode dash, NFKC (NBSP, U+3000, full-width),
  combining marks dropped, Cyrillic/Greek homoglyphs mapped to Latin.
- A project missing from a user's cached list triggers one reload of that
  list before `PROJECT_NOT_FOUND`.
- Every tool call does one `GET /api/v1/users/me/` (cached per user for
  `HANGAR_PROJECT_CACHE_SECONDS`; with 0 an extra GET per call).
- Write tools are always registered (12 tools); `hangar_writer` still gates
  them per call. `WRITES_DISABLED` and `PROJECT_NOT_WRITABLE` are gone.
- `HANGAR_ALLOWED_PROJECTS` is now an optional ceiling (empty = whatever
  Hangar lets the user see). A user with no projects gets an empty list, not
  an error.
- Audit line: `email` replaced by `plane_user_id`.
- `HANGAR_API_KEY` and `HANGAR_WRITE_PROJECTS` are retired: startup error if
  present (even empty), with a "retired, remove it" message.
- `scripts/live-smoke.mjs` expects 12 tools, lists up to 50 projects and
  prints the tool error code on a failed read.
- **Roles are bound to our ZITADEL organization** (security fix; the ZITADEL
  instance is shared with other products' organizations). A project role
  claim (`urn:zitadel:iam:org:project:<aud>:roles` or
  `urn:zitadel:iam:org:project:roles`) counts only when `claim[role]` is an
  object keyed by `MCP_OIDC_ALLOWED_ORG_ID`. Array forms, the legacy `roles`
  claim and `my:zitadel:grants` count only when
  `urn:zitadel:iam:user:resourceowner:id` equals that org (`org_id` is never
  used). The old organization check, which matched the org id anywhere in any
  `*:roles` claim (so our-org guest plus a foreign `hangar_writer` passed as
  writer), is removed: the role gate is the organization gate, for JWS and
  introspected tokens alike. Matches the Hangar (Plane) side.
- `MCP_OIDC_ALLOWED_ORG_ID` is now **required**: startup error when missing or
  empty.
- New Hangar answers mapped: 403 `DUMONT_USER_NOT_ALLOWED` (also the older
  401 form) becomes `USER_NOT_ALLOWED` (not retryable, a new login will not
  help); 503 `DUMONT_AUTH_UNAVAILABLE` becomes `UPSTREAM_AUTH_UNAVAILABLE`
  (retryable, also for writes since Hangar refused before running the view;
  never a new login). Hangar's 401 challenge now carries
  `error="invalid_token"`; it is still mapped by `error_code` and never
  becomes an MCP 401. The mapping is the same for JWS and opaque tokens.

### Owner steps

Follow README → "Manual deploy (0.3.0: acting as the user)". In short: deploy
and verify the Hangar side first, including `DUMONT_API_INTROSPECTION_*`
(opaque tokens are now forwarded; without it, opaque-token users get an error
from Hangar); then prepare `/etc/dumont-hangar-mcp.env.new`
as a copy without `HANGAR_API_KEY` and `HANGAR_WRITE_PROJECTS` and with
`MCP_CURSOR_SECRET` (compare the two project lists first: writes now reach
every project in `HANGAR_ALLOWED_PROJECTS` where the user is a Hangar Member),
make sure it has a non-empty `MCP_OIDC_ALLOWED_ORG_ID` (our ZITADEL org id;
the release refuses to start without it) and that every MCP user's
`hangar_*` grant was made in that org, validate the copy, then move it into place, switch and restart back to back. Every user must sign in once
to Hangar web with Dumont login. Revoke the bot token only after the release
is stable.

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
