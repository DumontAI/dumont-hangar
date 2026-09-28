# Hangar MCP server

MCP server for the Dumont Hangar (Plane) instance. It exposes Hangar projects,
work items, comments, states, labels and members to MCP clients, and (for users
with the `hangar_writer` role) lets them create work items, change their
fields, append to their descriptions and add comments.

The MCP **acts as the logged-in user**: every upstream call to Hangar API v1
carries the caller's own ZITADEL access token (`Authorization: Bearer <JWT>`,
the same token this server verified), so Hangar applies that user's workspace
and project permissions and records that user as the author. There is no bot
account and no shared API key any more.

Only **Streamable HTTP** (`dist/http.js`) is supported, behind ZITADEL OIDC.
The earlier API-key/stdio launcher and static MCP bearer mode are retired.

## Tools

| Tool                             | Kind  | Purpose                                                                    |
| -------------------------------- | ----- | -------------------------------------------------------------------------- |
| `hangar_list_projects`           | read  | Projects you can see (within the optional server ceiling)                  |
| `hangar_get_project`             | read  | One project by identifier or UUID                                          |
| `hangar_list_work_items`         | read  | Work items of a project, with state/assignee/label/priority/search filters |
| `hangar_get_work_item`           | read  | One work item by `HGR-5` or UUID                                           |
| `hangar_search_work_items`       | read  | Text search, one project or every project you can see                      |
| `hangar_list_work_item_comments` | read  | Comments of a work item                                                    |
| `hangar_list_states`             | read  | Workflow states of a project                                               |
| `hangar_list_labels`             | read  | Labels of a project                                                        |
| `hangar_list_members`            | read  | Workspace or project members (no emails)                                   |
| `hangar_create_work_item`        | write | Create a work item (optional `idempotency_key`)                            |
| `hangar_update_work_item`        | write | Change given fields, append to the description; no replace, no delete      |
| `hangar_add_comment`             | write | Comment on a work item                                                     |

All twelve tools are always listed. Write tools need the `hangar_writer` role
(checked by this server on every call) **and** write access to the project in
Hangar (Member or Admin; checked by Hangar).

Read tools are annotated read-only. Write tools are `readOnlyHint: false`,
`destructiveHint: false`, `idempotentHint: false`.

Text returned by the read tools is **redacted** (credentials, emails, IPs) and
**truncated** (8000 characters). It is for reading only: never write it back.
That is why update cannot replace a description, only append to it.

### Write tool inputs

- `hangar_create_work_item`: `project`, `name`, and optionally `description`
  (Markdown or plain text), `state` (name or UUID), `priority`
  (`urgent|high|medium|low|none`), `labels` (names or UUIDs), `assignees`
  (display names, UUIDs, or `"me"`), `parent` (`HGR-5`, same project),
  `start_date`/`target_date` (`YYYY-MM-DD`), `idempotency_key`.
- `hangar_update_work_item`: `work_item` (`HGR-5`, or UUID plus `project`) and
  any of `name`, `state`, `priority`, `labels`, `assignees`, `parent`,
  `start_date`, `target_date`, `append_description`. Only given fields change;
  `labels`/`assignees` replace the whole set; `parent`/`start_date`/`target_date`
  accept `null` to clear. Moving to a cancelled-group state is allowed; there is
  no delete. `description` is rejected (unknown key): `append_description`
  fetches the raw stored `description_html` server-side (never returned), and
  PATCHes it back unchanged followed by the new text and one footer. If Hangar
  does not return the stored description, nothing is written.
- `hangar_add_comment`: `work_item` (and `project` for a UUID), `body`.

Behavior common to all writes:

- **Authorship**: Hangar records the logged-in user as the author (the call is
  made with their token). The description on create, each
  `append_description`, and each comment end with the footer `— via MCP`,
  which names nobody. Every line of caller text shaped like a footer (em dash,
  then `via MCP`, then anything: both the current `— via MCP` and the retired
  `— via MCP por <name>`) is removed first, so footers never stack and nobody
  can forge an old-style attribution line naming someone else; lines starting
  with `-` or `--` are left alone. Footers already stored in Hangar are kept as
  they are.
- **Safe HTML**: input is escaped completely and converted from a small
  Markdown subset (paragraphs, headings, lists, quotes, code, bold/italic,
  http/https/mailto links) to `description_html`/`comment_html`. Links are
  replaced by placeholders before emphasis runs, so an href is never rewritten.
  Plane then sanitizes it again with nh3.
- **Credential refusal** (`SECRET_DETECTED`; nothing is written, the value is
  not echoed):
  - always: JWTs, PEM private keys, `plane_api_`, GitHub/GitLab/Slack tokens,
    AWS access key ids, `sk-` keys, Twilio `SID:secret`, and connection strings
    or URLs that embed a password;
  - for `key: value` / `key=value` with a credential key (`password`, `senha`,
    `pwd`, `passphrase`, `secret`, `client_secret`, `token`, `api_key`,
    `private_key`, `access_key`, `dsn`, `authorization`, `cookie`) and for
    `Bearer <value>`: only when the **value** looks like a secret: at least 12
    characters, not plain words, not an http(s) URL without userinfo, and
    mixing letters and digits or of high entropy.

  So prose like `O token: expirado ontem`, `token=undefined`,
  `tokenUrl: https://…` or `secret: HANGAR_API_KEY` goes through, while
  `senha: minhasenha123` or `pwd=Sup3rS3cret!x9` is refused.

- **`"me"`** resolves to the Hangar user behind the caller's token
  (`GET /api/v1/users/me/`, cached per user).
- **Idempotency**: `idempotency_key` becomes Plane `external_id`
  (`<sha256(sub)[:16]>:<key>`, so keys are per user) with
  `external_source=dumont-hangar-mcp`. Plane answers a repeat with 409 and the
  existing id (`apps/api/plane/api/views/issue.py`,
  `IssueListCreateAPIEndpoint.post`); the tool then returns that item with
  `idempotent_replay: true`.
- **Rate limit**: `HANGAR_WRITE_RATE_LIMIT` write calls per user (`sub`) per
  fixed 60 s window, shared across requests of the process; over the limit the
  tool returns `RATE_LIMITED` with `retryable: true`.

### Acting as the user

- **Which token is forwarded**: only a JWS access token this server verified
  locally (RS256, issuer, audience, lifetime, role) is sent to Hangar, and
  only to `HANGAR_BASE_URL` (HTTPS, no redirects followed). It is never logged
  or stored; it lives in the per-request Hangar client only. An opaque (JWE)
  token that passed introspection is accepted by this server but is **not
  forwarded** (Hangar accepts only JWTs): its tool calls answer
  `TOKEN_NOT_FORWARDABLE`, asking the user to connect with the pinned public
  client (which issues JWTs).
- **Per-request isolation**: the HTTP layer builds a new McpServer and a new
  Hangar client bound to the verified caller for every request; there is no
  global "current user".
- **Caches are per user**: the project list, the workspace member list and the
  Hangar user id are cached per token `sub` (`HANGAR_PROJECT_CACHE_SECONDS`,
  at most 1000 users, least recently used dropped first). One user's cached
  data is never served to another user. The cache only helps name resolution;
  Hangar still authorizes every call.
- **Cursors are per user**: pagination cursors are HMAC-signed with
  `MCP_CURSOR_SECRET` and bound to the caller's `sub`; a cursor issued to one
  user is `INVALID_CURSOR` for anyone else.
- **Hangar 401 is not an MCP 401**: a 401 from Hangar becomes a tool error
  (HTTP 200), so the client does not restart its login for a problem a new
  login cannot fix. The only exception is an expired token: when Hangar
  answers 401 and the token is at most 60 s from its `exp`, the tool answers
  `TOKEN_EXPIRED` (retryable), and the client's next request with that token
  gets this server's regular 401 challenge and refreshes the login.

### Error codes (tool errors, HTTP 200)

| Code                    | Meaning                                                                                                       |
| ----------------------- | ------------------------------------------------------------------------------------------------------------- |
| `FORBIDDEN`             | Token lacks the role for this tool (write tools need `hangar_writer`)                                         |
| `ACCOUNT_NOT_LINKED`    | Hangar has no account linked to this Dumont login: sign in once at https://hangar.getdumont.ai (Dumont login) |
| `TOKEN_NOT_FORWARDABLE` | Opaque token; connect with the pinned public client (JWT) and log in again                                    |
| `TOKEN_EXPIRED`         | Token expired during the call; retry (the client refreshes on the next request)                               |
| `WRITER_ROLE_REQUIRED`  | Hangar requires `hangar_writer` for this change                                                               |
| `PROJECT_ACCESS_DENIED` | Hangar denied access to project X; ask for role `hangar.project.x.member` in Dumont Auth                      |
| `PROJECT_NOT_FOUND`     | Not among the projects you can see (the message names the role to ask for)                                    |
| `PROJECT_NOT_ALLOWED`   | Project is outside this server's `HANGAR_ALLOWED_PROJECTS` ceiling                                            |
| `SECRET_DETECTED`       | Input looked like a credential; nothing written                                                               |
| `RATE_LIMITED`          | Per-user write limit reached; retry after the window                                                          |
| `UPSTREAM_*`            | Hangar refused or failed; `UPSTREAM_VALIDATION_FAILED` lists fields                                           |

A write that times out or gets a 5xx is **not** marked retryable: it may have
been applied. Use `idempotency_key` for safe retries of creates.

## Roles and access

Two separate layers:

| Layer                 | Where it is managed                             | What it decides                                           |
| --------------------- | ----------------------------------------------- | --------------------------------------------------------- |
| MCP gate              | ZITADEL roles `hangar_reader` / `hangar_writer` | May this user use the read tools / the write tools at all |
| Hangar access (Plane) | Hangar workspace/project membership of the user | Which projects the user sees and where they may write     |

- `hangar_reader` grants the read tools; `hangar_writer` grants the read and
  write tools (implies read). Hangar also requires `hangar_writer` on the
  token for any change (`WRITER_ROLE_REQUIRED` otherwise).
- Hangar membership is per user. For projects managed by Dumont Auth, it
  follows the ZITADEL roles `hangar.project.<identifier>.admin|member|guest`
  (e.g. `hangar.project.hgr.member`); writing needs Member or Admin.
- `HANGAR_ALLOWED_PROJECTS` is an optional ceiling on top: when set, the MCP
  refuses every project outside it, whatever Hangar would allow.
- The HTTP layer accepts a token that carries **either** role. A token with
  neither role is `403 insufficient_scope`. A reader calling a write tool gets a
  `FORBIDDEN` tool error, not an HTTP 401/403, so clients do not restart login.
- Protected-resource metadata `scopes_supported` and the `WWW-Authenticate`
  `scope=` list, in order: `openid`, `email`,
  `urn:zitadel:iam:org:project:role:hangar_reader`,
  `urn:zitadel:iam:org:project:role:hangar_writer`. ZITADEL only asserts roles
  the client requested, so clients must request both role scopes. `openid` and
  `email` stay advertised so existing client logins do not change; none of
  these has to be present in the token.
- `MCP_OIDC_REQUIRED_ROLE` (pre-HGR-6) is still read as the reader role.
- Where roles are read from (token already bound to issuer and audience):
  `urn:zitadel:iam:org:project:<audience>:roles` (only the audience project's
  roles); `urn:zitadel:iam:org:project:roles` and `roles` (roles of the
  requesting application's project: our clients live in the audience project,
  but a client of another project that also requests our audience would carry
  that project's roles here, so no other ZITADEL project may define roles named
  `hangar_reader`/`hangar_writer`); `my:zitadel:grants` only as the exact
  `<audience>:<role>` string. Hangar applies the same rules to the forwarded
  token.

## Audit log

One JSON line per tool call (read and write) on stderr, i.e. in journald for
`dumont-hangar-mcp.service`:

```json
{
  "ts": "…",
  "event": "hangar.mcp.tool",
  "tool": "hangar_create_work_item",
  "sub": "…",
  "plane_user_id": "…",
  "roles_used": ["hangar_writer"],
  "project": "HGR",
  "work_item": "HGR-12",
  "fields_changed": ["name", "description"],
  "outcome": "success",
  "error_code": null,
  "latency_ms": 184
}
```

`plane_user_id` is the Hangar user behind the token (from
`GET /api/v1/users/me/`, cached per user); it can be `null` when Hangar was
not or could not be asked (unlinked account, opaque token, a role denial
before any call with nothing cached yet).
`outcome` is `success`, `denied` (policy: role, ceiling, secret, rate, or a
Hangar denial such as `PROJECT_ACCESS_DENIED`/`ACCOUNT_NOT_LINKED`) or
`error`. `fields_changed` are field names only (on an error, the fields that
were attempted). Text bodies, tokens and emails are never logged;
caller-supplied references that do not look like an identifier or UUID are
logged as `[invalid]`.

`journalctl -u dumont-hangar-mcp -o cat | grep '"hangar.mcp.tool"'`

## Configuration

See [.env.example](.env.example). The important ones:

| Variable                       | Meaning                                                                             |
| ------------------------------ | ----------------------------------------------------------------------------------- |
| `HANGAR_BASE_URL`              | Hangar origin, default `https://hangar.getdumont.ai`; the caller's token goes here  |
| `HANGAR_WORKSPACE_SLUG`        | Workspace slug                                                                      |
| `HANGAR_ALLOWED_PROJECTS`      | Optional ceiling: CSV of identifiers (`HGR`) or UUIDs. Empty = no ceiling           |
| `MCP_CURSOR_SECRET`            | **Required**, at least 32 bytes: HMAC key of the pagination cursors. Secret         |
| `HANGAR_WRITE_RATE_LIMIT`      | Write calls per user per 60 s, default 20, max 120                                  |
| `HANGAR_PROJECT_CACHE_SECONDS` | Per-user cache TTL (projects, members, user id), default 60, 0 disables             |
| `MCP_AUTH_MODE`                | `oidc` only                                                                         |
| `MCP_RESOURCE_URL`             | Public MCP URL, `https://hangar.getdumont.ai/mcp`                                   |
| `MCP_OIDC_AUDIENCE`            | ZITADEL project audience (the `ZITADEL DCR` project); Hangar must accept it as well |
| `MCP_OIDC_READER_ROLE`         | `hangar_reader` (legacy name: `MCP_OIDC_REQUIRED_ROLE`)                             |
| `MCP_OIDC_WRITER_ROLE`         | `hangar_writer`                                                                     |
| `MCP_OIDC_INTROSPECTION_*`     | Optional RFC 7662 introspection for opaque tokens (never forwarded to Hangar)       |

Retired keys:

| Variable                | Status                                                                           |
| ----------------------- | -------------------------------------------------------------------------------- |
| `HANGAR_API_KEY`        | **Startup error if present, even empty** ("retired, remove it"): no bot any more |
| `HANGAR_WRITE_PROJECTS` | **Startup error if present, even empty**: Hangar membership decides writes       |
| `MCP_OIDC_USERINFO_URL` | Ignored (no more email lookup); remove it                                        |

Hangar side (fork module `apps/api/plane/dumont/`): API v1 must accept the
bearer, i.e. `DUMONT_API_BEARER_ENABLED=1` with `MCP_OIDC_AUDIENCE` listed in
`DUMONT_API_AUDIENCES`.

## Team access with login

Point compatible clients at `https://hangar.getdumont.ai/mcp` and pin the
pre-registered public client (`392047847798800387`, redirect
`http://127.0.0.1:19876/mcp/oauth/callback`, PKCE, no secret). The client opens
the Dumont login; the token must carry `hangar_reader` or `hangar_writer`.

For a new teammate, in this order:

1. **Dumont Auth (ZITADEL)**: grant `hangar_reader` (or `hangar_writer`) in
   the `ZITADEL DCR` project, plus the Hangar project roles they need (e.g.
   `hangar.project.hgr.member`) where projects are managed by Dumont Auth.
2. **Hangar web, once**: they sign in at https://hangar.getdumont.ai with
   **Dumont login**. That links their ZITADEL user to a Hangar account; until
   then every tool answers `ACCOUNT_NOT_LINKED`.
3. **MCP client**: connect with the pinned client above and log in.

Do not let the client self-register through ZITADEL DCR: those applications
receive opaque (JWE) access tokens, which Hangar cannot accept; the tools then
answer `TOKEN_NOT_FORWARDABLE`.

After `hangar_writer` is granted, a client must **log in again** so the new
token requests and carries the role (Claude Code: `/mcp`, pick the Hangar
server, re-authenticate; dumont-code: expire/remove the stored Hangar token so
the next call opens the login). Project-role changes in Hangar need no new
MCP login.

dumont-code example:

```jsonc
"mcp": {
  "hangar": {
    "type": "remote",
    "url": "https://hangar.getdumont.ai/mcp",
    "enabled": true,
    "oauth": { "clientId": "392047847798800387" }
  }
}
```

## Deployment (hel1)

- Releases live under `/opt/dumont-hangar-mcp/releases/<release>`, active
  symlink `/opt/dumont-hangar-mcp/current`; each release has a `RELEASE` file
  (`release_id`, `source_commit`, `source_ref`).
- `dumont-hangar-mcp.service` runs `dist/http.js` on `127.0.0.1:3014` as
  `deploy`, reading `/etc/dumont-hangar-mcp.env` (`root:deploy`, mode `0640`).
- Caddy on `hangar.getdumont.ai` routes `/mcp` and the protected-resource
  metadata paths to `127.0.0.1:3014`; everything else stays with the Hangar
  stack.
- Caddy must return `410 Gone` for `/hangar-mcp` before the Hangar catch-all:
  `handle /hangar-mcp { respond "The API-key Hangar MCP was retired. Use https://hangar.getdumont.ai/mcp with Dumont login." 410 }`.
  This prevents the old web image from distributing the API-key launcher while
  a refreshed image is pending.

### CI

`.github/workflows/hangar-mcp.yml` runs typecheck, tests and build on
GitHub-hosted `ubuntu-latest` for PRs and for pushes to `dumont` that touch
`mcp/**`. This repository is **public**, so the workflow has read-only
permissions, no secrets, no self-hosted runner and **no deploy job**. Deploys
are manual (below); an automated deploy is left to a later ticket, driven from
a private repository.

### Manual deploy (0.3.0: acting as the user)

**Order matters.** This release calls Hangar with the user's token, so Hangar
must accept it first, and this release refuses to start while
`HANGAR_API_KEY` or `HANGAR_WRITE_PROJECTS` is in the env file. So:

0. **Prerequisite (Hangar side, deployed and verified first)**: Hangar runs
   the fork release with the Dumont bearer (`apps/api/plane/dumont/`), with
   `DUMONT_API_BEARER_ENABLED=1` and `DUMONT_API_AUDIENCES` containing the
   value of `MCP_OIDC_AUDIENCE`. Every MCP user has signed in once to Hangar
   web with Dumont login (otherwise `ACCOUNT_NOT_LINKED`) and is a member of
   the projects they use. **Do not remove `HANGAR_API_KEY` /
   `HANGAR_WRITE_PROJECTS` before this is live**: the old MCP release (still
   running) needs them, and the new one cannot work without the Hangar side.

Never `cat` the env file: it holds secrets. Print key names only.

1. **Build locally** from the commit being released (repo root):

   ```bash
   (cd mcp && pnpm install --frozen-lockfile --ignore-workspace \
     && pnpm run typecheck && pnpm test && rm -rf dist && pnpm run build)
   SHA=$(git rev-parse --short=12 HEAD)
   tar -czf "hangar-mcp-$SHA.tar.gz" mcp/dist mcp/package.json mcp/pnpm-lock.yaml
   scp "hangar-mcp-$SHA.tar.gz" airbase-hel1:/tmp/
   ```

2. **Stage the release** on airbase-hel1 as `deploy`:

   ```bash
   SHA=<same sha>; REL=/opt/dumont-hangar-mcp/releases/$SHA-manual
   readlink -f /opt/dumont-hangar-mcp/current | tee /tmp/hangar-mcp-previous-release
   mkdir "$REL" && tar -xzf "/tmp/hangar-mcp-$SHA.tar.gz" -C "$REL"
   (cd "$REL/mcp" && pnpm install --prod --frozen-lockfile --ignore-scripts --ignore-workspace)
   printf 'release_id=%s\nsource_commit=%s\nsource_ref=manual\n' "$SHA-manual" "$SHA" > "$REL/RELEASE"
   ```

3. **Edit the env file** (only after step 0; back up first). The backup keeps
   the old API key for a rollback; it has the same owner and mode as the
   original.

   ```bash
   sudo cp -p /etc/dumont-hangar-mcp.env /etc/dumont-hangar-mcp.env.bak-$SHA
   sudo sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' /etc/dumont-hangar-mcp.env   # names only
   # Remove the retired keys (and the no-longer-read userinfo URL, if present).
   sudo sed -i -e '/^HANGAR_API_KEY=/d' -e '/^HANGAR_WRITE_PROJECTS=/d' \
     -e '/^MCP_OIDC_USERINFO_URL=/d' /etc/dumont-hangar-mcp.env
   # Add the new cursor secret, generated on the host and never printed.
   printf 'MCP_CURSOR_SECRET="%s"\n' "$(openssl rand -hex 32)" | sudo tee -a /etc/dumont-hangar-mcp.env >/dev/null
   sudo sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' /etc/dumont-hangar-mcp.env   # names only, check
   ```

   The running (old) release is unaffected until the restart in step 5, since
   systemd read the env at start. `HANGAR_ALLOWED_PROJECTS` stays as it is: it
   is now an optional ceiling. Emptying it later lets each user reach every
   project Hangar shows them.

4. **Validate the config with the new release** before switching. `systemd-run`
   reads the env file exactly as the service does and runs the check as
   `deploy`; secrets stay in the unit's environment, never in argv or output:

   ```bash
   sudo systemd-run --pipe --wait --quiet --collect \
     -p EnvironmentFile=/etc/dumont-hangar-mcp.env -p User=deploy -p Group=deploy \
     -p WorkingDirectory="$REL" \
     /usr/bin/node --input-type=module -e '
       const m = await import("./mcp/dist/config.js");
       try { const c = m.loadHangarConfig(); m.assertHttpAuthConfigured(c);
         console.log("OK project ceiling=" + (c.allowedProjects.join(",") || "none")); }
       catch (e) { console.error("ERROR " + e.message); process.exit(1); }'
   ```

   `ERROR HANGAR_API_KEY is retired, remove it…` means step 3 did not remove
   it; `ERROR MCP_CURSOR_SECRET is required…` means the secret is missing.

5. **Switch and restart**:

   ```bash
   ln -s "$REL" /opt/dumont-hangar-mcp/.current.new
   mv -Tf /opt/dumont-hangar-mcp/.current.new /opt/dumont-hangar-mcp/current
   sudo systemctl restart dumont-hangar-mcp.service
   systemctl is-active dumont-hangar-mcp.service
   ```

6. **Check** (loopback 401, challenge scopes, metadata, logs):

   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:3014/mcp          # 401
   curl -s -D - -o /dev/null -X POST http://127.0.0.1:3014/mcp | grep -i www-authenticate
   # expect scope="openid email ...:hangar_reader ...:hangar_writer"
   curl -s http://127.0.0.1:3014/.well-known/oauth-protected-resource                  # scopes_supported
   sudo journalctl -u dumont-hangar-mcp -n 20 --no-pager
   ```

   The scripted metadata check (copy `mcp/scripts/metadata-smoke.mjs` to the
   host, or run it from a checkout through an SSH tunnel to port 3014):

   ```bash
   MCP_METADATA_URL=http://127.0.0.1:3014/.well-known/oauth-protected-resource \
   MCP_RESOURCE_URL=https://hangar.getdumont.ai/mcp \
   MCP_OIDC_ISSUER=https://auth.getdumont.ai \
     node metadata-smoke.mjs
   ```

   Then the authenticated read smoke with a real user's short-lived JWT
   (`mcp/scripts/live-smoke.mjs`, `MCP_AUTH_TOKEN` from the environment, never
   in argv): it expects 12 tools and prints the number of projects **that
   user** sees. `HANGAR_PROJECTS_READ_FAILED:ACCOUNT_NOT_LINKED` means that
   user never signed in to Hangar web with Dumont login;
   `…:UPSTREAM_UNAUTHORIZED` means Hangar does not accept the bearer (step 0).
   In the journal, audit lines now carry `plane_user_id` and no email.

7. **Rollback**: the previous release needs the old env file (with
   `HANGAR_API_KEY`), so restore the backup, switch the symlink back and
   restart:

   ```bash
   sudo cp -p /etc/dumont-hangar-mcp.env.bak-$SHA /etc/dumont-hangar-mcp.env
   ln -s "$(cat /tmp/hangar-mcp-previous-release)" /opt/dumont-hangar-mcp/.current.new
   mv -Tf /opt/dumont-hangar-mcp/.current.new /opt/dumont-hangar-mcp/current
   sudo systemctl restart dumont-hangar-mcp.service
   ```

8. **After it is stable**: revoke the old bot API token of
   `hangar-mcp@dumont.au` in Hangar (only after confirming nothing else uses
   it) and delete `/etc/dumont-hangar-mcp.env.bak-*`, which still hold it.
   Rollback past this point needs a new bot token.

The historical downloadable `/hangar-mcp` launcher is disabled. Older local
copies cannot be disabled by a server release: remove their MCP registrations
and revoke their personal Hangar tokens only after confirming no other API use.
