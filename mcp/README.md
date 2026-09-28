# Hangar MCP server

MCP server for the Dumont Hangar (Plane) instance. It exposes Hangar projects,
work items, comments, states, labels and members to MCP clients, and (for users
with the `hangar_writer` role, in write-enabled projects) lets them create work
items, change their fields, append to their descriptions and add comments. The caller's credential is never forwarded
to Hangar: upstream calls use a server-side Hangar API token (bot
`hangar-mcp@dumont.au`), and every write is attributed to the logged-in user in
a footer and in the audit log.

Only **Streamable HTTP** (`dist/http.js`) is supported, behind ZITADEL OIDC.
The earlier API-key/stdio launcher and static MCP bearer mode are retired.

## Tools

| Tool                             | Kind  | Purpose                                                                    |
| -------------------------------- | ----- | -------------------------------------------------------------------------- |
| `hangar_list_projects`           | read  | Projects in the server allowlist                                           |
| `hangar_get_project`             | read  | One project by identifier or UUID                                          |
| `hangar_list_work_items`         | read  | Work items of a project, with state/assignee/label/priority/search filters |
| `hangar_get_work_item`           | read  | One work item by `HGR-5` or UUID                                           |
| `hangar_search_work_items`       | read  | Text search, one project or the whole allowlist                            |
| `hangar_list_work_item_comments` | read  | Comments of a work item                                                    |
| `hangar_list_states`             | read  | Workflow states of a project                                               |
| `hangar_list_labels`             | read  | Labels of a project                                                        |
| `hangar_list_members`            | read  | Workspace or project members (no emails)                                   |
| `hangar_create_work_item`        | write | Create a work item (optional `idempotency_key`)                            |
| `hangar_update_work_item`        | write | Change given fields, append to the description; no replace, no delete      |
| `hangar_add_comment`             | write | Comment on a work item                                                     |

Write tools are **registered only when `HANGAR_WRITE_PROJECTS` is set**; a
read-only server lists just the nine read tools.

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

- **Attribution**: the description on create, each `append_description`, and
  each comment end with `— via MCP por <email>`. Every line of caller text
  shaped like that footer (em dash, `via MCP por`, a name) is removed first, so
  footers never stack and a caller cannot forge someone else's attribution;
  lines starting with `-` or `--` are left alone. The email comes from the
  caller (see "Caller email" below); if none is found the footer names the
  token `sub`.
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

- **`"me"`** resolves to the Hangar workspace member whose email equals the
  caller email (below). Without an email, or without exactly one matching
  member, `"me"` fails with `FORBIDDEN`.
- **Idempotency**: `idempotency_key` becomes Plane `external_id`
  (`<sha256(sub)[:16]>:<key>`, so keys are per user) with
  `external_source=dumont-hangar-mcp`. Plane answers a repeat with 409 and the
  existing id (`apps/api/plane/api/views/issue.py`,
  `IssueListCreateAPIEndpoint.post`); the tool then returns that item with
  `idempotent_replay: true`.
- **Rate limit**: `HANGAR_WRITE_RATE_LIMIT` write calls per user (`sub`) per
  fixed 60 s window, shared across requests of the process; over the limit the
  tool returns `RATE_LIMITED` with `retryable: true`.

### Caller email

ZITADEL JWT access tokens usually carry no `email`. The server resolves it
only when a write needs it (footer or `"me"`), never for reads:

1. the token's `email` claim, only when `email_verified` is exactly `true`;
2. otherwise the issuer's userinfo endpoint, called with the caller's own
   bearer (`MCP_OIDC_USERINFO_URL`, default `${MCP_OIDC_ISSUER}/oidc/v1/userinfo`,
   must be on the issuer's origin; 2 s timeout, no redirects, 64 KiB cap, the
   returned `sub` must match). It takes `email` only when `email_verified` is
   exactly `true`. `preferred_username` is never used (a user may be able to
   set it to someone else's address). Results are cached per `sub` (10 min
   when found, 60 s when not, at most 1000 entries).

Any failure falls back to the `sub` and never fails the tool call; stderr gets
one line per failure class per minute (`hangar-mcp userinfo-email outcome=…`,
no token). ZITADEL returns `email` from userinfo only when the token was issued
with the `openid email` scopes, which is why the server advertises them.

### Error codes (tool errors, HTTP 200)

| Code                   | Meaning                                                             |
| ---------------------- | ------------------------------------------------------------------- |
| `FORBIDDEN`            | Token lacks the role for this tool, or `"me"` could not be resolved |
| `WRITES_DISABLED`      | Defensive only: with writes off the write tools are not registered  |
| `PROJECT_NOT_ALLOWED`  | Project is not in `HANGAR_ALLOWED_PROJECTS`                         |
| `PROJECT_NOT_WRITABLE` | Project is readable but not in `HANGAR_WRITE_PROJECTS`              |
| `SECRET_DETECTED`      | Input looked like a credential; nothing written                     |
| `RATE_LIMITED`         | Per-user write limit reached; retry after the window                |
| `UPSTREAM_*`           | Hangar refused or failed; `UPSTREAM_VALIDATION_FAILED` lists fields |

A write that times out or gets a 5xx is **not** marked retryable: it may have
been applied. Use `idempotency_key` for safe retries of creates.

## Roles and scopes

| Role            | Grants                                    |
| --------------- | ----------------------------------------- |
| `hangar_reader` | Read tools                                |
| `hangar_writer` | Read tools and write tools (implies read) |

- The HTTP layer accepts a token that carries **either** role. A token without
  neither role is `403 insufficient_scope`. A reader calling a write tool gets a
  `FORBIDDEN` tool error, not an HTTP 401/403, so clients do not restart login.
- Protected-resource metadata `scopes_supported` and the `WWW-Authenticate`
  `scope=` list, in order: `openid`, `email`,
  `urn:zitadel:iam:org:project:role:hangar_reader`,
  `urn:zitadel:iam:org:project:role:hangar_writer`. ZITADEL only asserts roles
  the client requested, so clients must request both role scopes; `openid` and
  `email` let userinfo return the caller's email. None of these has to be
  present in the token: a token with only `hangar_reader` is still accepted for
  reads.
- `MCP_OIDC_REQUIRED_ROLE` (pre-HGR-6) is still read as the reader role.
- Where roles are read from (token already bound to issuer and audience):
  `urn:zitadel:iam:org:project:<audience>:roles` (only the audience project's
  roles); `urn:zitadel:iam:org:project:roles` and `roles` (roles of the
  requesting application's project: our clients live in the audience project,
  but a client of another project that also requests our audience would carry
  that project's roles here, so no other ZITADEL project may define roles named
  `hangar_reader`/`hangar_writer`); `my:zitadel:grants` only as the exact
  `<audience>:<role>` string.

## Audit log

One JSON line per tool call (read and write) on stderr, i.e. in journald for
`dumont-hangar-mcp.service`:

```json
{
  "ts": "…",
  "event": "hangar.mcp.tool",
  "tool": "hangar_create_work_item",
  "sub": "…",
  "email": "…",
  "roles_used": ["hangar_writer"],
  "project": "HGR",
  "work_item": "HGR-12",
  "fields_changed": ["name", "description"],
  "outcome": "success",
  "error_code": null,
  "latency_ms": 184
}
```

`outcome` is `success`, `denied` (policy: role, disabled, allowlist, secret,
rate) or `error`. `fields_changed` are field names only (on an error, the
fields that were attempted). Text bodies, tokens and the API key are never
logged; caller-supplied references that do not look like an identifier or UUID
are logged as `[invalid]`.

`journalctl -u dumont-hangar-mcp -o cat | grep '"hangar.mcp.tool"'`

## Configuration

See [.env.example](.env.example). The important ones:

| Variable                   | Meaning                                                                 |
| -------------------------- | ----------------------------------------------------------------------- |
| `HANGAR_BASE_URL`          | Hangar origin, default `https://hangar.getdumont.ai`                    |
| `HANGAR_API_KEY`           | Dedicated Hangar bot token. Server-side only                            |
| `HANGAR_WORKSPACE_SLUG`    | Workspace slug                                                          |
| `HANGAR_ALLOWED_PROJECTS`  | CSV of identifiers (`HGR`) or project UUIDs readable through the MCP    |
| `HANGAR_WRITE_PROJECTS`    | Subset of the above (same spelling) where writes are allowed; empty=off |
| `HANGAR_WRITE_RATE_LIMIT`  | Write calls per user per 60 s, default 20, max 120                      |
| `MCP_AUTH_MODE`            | `oidc` only                                                             |
| `MCP_RESOURCE_URL`         | Public MCP URL, `https://hangar.getdumont.ai/mcp`                       |
| `MCP_OIDC_AUDIENCE`        | ZITADEL project audience (the `ZITADEL DCR` project)                    |
| `MCP_OIDC_READER_ROLE`     | `hangar_reader` (legacy name: `MCP_OIDC_REQUIRED_ROLE`)                 |
| `MCP_OIDC_WRITER_ROLE`     | `hangar_writer`                                                         |
| `MCP_OIDC_USERINFO_URL`    | Optional; default `${MCP_OIDC_ISSUER}/oidc/v1/userinfo`, same origin    |
| `MCP_OIDC_INTROSPECTION_*` | Optional RFC 7662 introspection for opaque tokens                       |

`HANGAR_WRITE_PROJECTS` is checked at startup against
`HANGAR_ALLOWED_PROJECTS` literally (after upper-casing identifiers), so an
identifier in one list cannot be matched to a UUID in the other.

The bot account behind `HANGAR_API_KEY` must be a **Member** (not Guest) of
every write project, or Hangar answers `UPSTREAM_FORBIDDEN`.

## Team access with login

Point compatible clients at `https://hangar.getdumont.ai/mcp` and pin the
pre-registered public client (`392047847798800387`, redirect
`http://127.0.0.1:19876/mcp/oauth/callback`, PKCE, no secret). The client opens
the Dumont login; the token must carry `hangar_reader` or `hangar_writer`. Do
not let the client self-register through ZITADEL DCR: those applications
receive opaque (JWE) access tokens, which only work when the introspection
credentials are configured.

After `hangar_writer` is granted, a client must **log in again** so the new
token requests and carries the role (Claude Code: `/mcp`, pick the Hangar
server, re-authenticate; dumont-code: expire/remove the stored Hangar token so
the next call opens the login). Clients that request the advertised scopes
also get `openid email`, which the email lookup needs.

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

### CI

`.github/workflows/hangar-mcp.yml` runs typecheck, tests and build on
GitHub-hosted `ubuntu-latest` for PRs and for pushes to `dumont` that touch
`mcp/**`. This repository is **public**, so the workflow has read-only
permissions, no secrets, no self-hosted runner and **no deploy job**. Deploys
are manual (below); an automated deploy is left to a later ticket, driven from
a private repository.

### Manual deploy (keeps the existing env file)

It keeps `/etc/dumont-hangar-mcp.env` as is and only appends the new non-secret
keys.
Never `cat` that file: it holds the API key.

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

3. **Add only the new non-secret keys** (back up first; print key names only):

   ```bash
   sudo cp -p /etc/dumont-hangar-mcp.env /etc/dumont-hangar-mcp.env.bak-$SHA
   sudo sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' /etc/dumont-hangar-mcp.env   # names only
   printf '%s\n' 'HANGAR_WRITE_PROJECTS=""' 'HANGAR_WRITE_RATE_LIMIT="20"' \
     'MCP_OIDC_WRITER_ROLE="hangar_writer"' | sudo tee -a /etc/dumont-hangar-mcp.env >/dev/null
   ```

   Leave `MCP_OIDC_REQUIRED_ROLE` as it is (it is read as the reader role; do
   not add `MCP_OIDC_READER_ROLE` with a different value). Leave
   `MCP_OIDC_USERINFO_URL` unset to use `${issuer}/oidc/v1/userinfo`. Start
   with `HANGAR_WRITE_PROJECTS=""` (writes off); set it to `"HGR"` with
   `sudoedit` later and restart. The unauthenticated checks below (401 and
   metadata) work whatever `MCP_ALLOWED_HOSTS` says; `127.0.0.1` is only needed
   there for an authenticated call over loopback (`mcp/scripts/live-smoke.mjs`).

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
         console.log("OK write projects=" + c.writeProjects.length); }
       catch (e) { console.error("ERROR " + e.message); process.exit(1); }'
   ```

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

7. **Rollback**: switch the symlink back and restart; restore the env backup
   only if you changed keys other than the appended ones.

   ```bash
   ln -s "$(cat /tmp/hangar-mcp-previous-release)" /opt/dumont-hangar-mcp/.current.new
   mv -Tf /opt/dumont-hangar-mcp/.current.new /opt/dumont-hangar-mcp/current
   sudo systemctl restart dumont-hangar-mcp.service
   ```

   The appended keys are harmless for the previous release (it ignores them).

The historical downloadable `/hangar-mcp` launcher is disabled. Older local
copies cannot be disabled by a server release: remove their MCP registrations
and revoke their personal Hangar tokens only after confirming no other API use.
