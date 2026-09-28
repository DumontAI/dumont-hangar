# Hangar MCP server

MCP server for the Dumont Hangar (Plane) instance. It exposes Hangar projects,
work items, comments, states, labels and members to MCP clients, and (for users
with the `hangar_writer` role, in write-enabled projects) lets them create and
update work items and add comments. The caller's credential is never forwarded
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
| `hangar_update_work_item`        | write | Change given fields of a work item; no delete                              |
| `hangar_add_comment`             | write | Comment on a work item                                                     |

Read tools are annotated read-only. Write tools are `readOnlyHint: false`,
`destructiveHint: false`; update is idempotent, create and comment are not.
Text fields are credential-scrubbed before they leave the server.

### Write tool inputs

- `hangar_create_work_item`: `project`, `name`, and optionally `description`
  (Markdown or plain text), `state` (name or UUID), `priority`
  (`urgent|high|medium|low|none`), `labels` (names or UUIDs), `assignees`
  (display names, UUIDs, or `"me"`), `parent` (`HGR-5`, same project),
  `start_date`/`target_date` (`YYYY-MM-DD`), `idempotency_key`.
- `hangar_update_work_item`: `work_item` (`HGR-5`, or UUID plus `project`) and
  any of the fields above. Only given fields change; `labels`/`assignees`
  replace the whole set; `parent`/`start_date`/`target_date` accept `null` to
  clear. Moving to a cancelled-group state is allowed; there is no delete.
- `hangar_add_comment`: `work_item` (and `project` for a UUID), `body`.

Behavior common to all writes:

- **Attribution**: descriptions (on create, and on update when a description is
  given) and comments end with `— via MCP por <email>`. A footer copied back
  into the input is removed first, so footers never stack. The email comes
  from the caller (see "Caller email" below); if none is found the footer
  names the token `sub`.
- **Safe HTML**: input is escaped completely and converted from a small
  Markdown subset (paragraphs, headings, lists, quotes, code, bold/italic,
  http/https/mailto links) to `description_html`/`comment_html`. Plane then
  sanitizes it again with nh3.
- **Credential refusal**: any input text that looks like a credential (bearer
  or authorization values, `password=`/`token:`-style assignments, connection
  strings or URLs with a password, private keys, JWTs, `plane_api_`, GitHub,
  Slack, AWS, OpenAI/Anthropic-style keys) is refused with `SECRET_DETECTED`;
  nothing is written and the value is not echoed. Naming a secret
  (`secret: HANGAR_API_KEY`) is fine.
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

1. the token's `email` claim, unless `email_verified` is false;
2. otherwise the issuer's userinfo endpoint, called with the caller's own
   bearer (`MCP_OIDC_USERINFO_URL`, default `${MCP_OIDC_ISSUER}/oidc/v1/userinfo`,
   must be on the issuer's origin; 2 s timeout, no redirects, 64 KiB cap, the
   returned `sub` must match). It takes `email` (unless `email_verified` is
   false), else `preferred_username` when it looks like an email. Results are
   cached per `sub` (10 min when found, 60 s when not, at most 1000 entries).

Any failure falls back to the `sub` and never fails the tool call; stderr gets
one line per failure class per minute (`hangar-mcp userinfo-email outcome=…`,
no token). ZITADEL returns `email` from userinfo only when the token was issued
with the `openid email` scopes, which is why the server advertises them.

### Error codes (tool errors, HTTP 200)

| Code                   | Meaning                                                             |
| ---------------------- | ------------------------------------------------------------------- |
| `FORBIDDEN`            | Token lacks the role for this tool, or `"me"` could not be resolved |
| `WRITES_DISABLED`      | `HANGAR_WRITE_PROJECTS` is empty                                    |
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

### Deploy workflow

`.github/workflows/hangar-mcp.yml`:

This repository is **public**, so code from pull requests must never reach a
self-hosted runner:

- **CI** runs on GitHub-hosted `ubuntu-latest` for every PR and for pushes to
  `dumont` that touch `mcp/**`, the workflow, or `scripts/deploy-mcp-hel1.sh`:
  install (`--ignore-workspace`, `mcp/` is not in the root pnpm workspace),
  typecheck, test, build, `bash -n` on the deploy script. It uploads nothing.
- **Deploy** is the only self-hosted job. It runs only on `workflow_dispatch`
  (write access required) from `refs/heads/dumont` with `deploy=true` and
  `confirmation=DEPLOY_HANGAR_MCP`, in the GitHub environment `production`, and
  after CI passed in the same run. It checks out the dispatched commit, installs,
  typechecks, tests, builds and packages the tarball itself, runs
  `scripts/deploy-mcp-hel1.sh`, then the metadata smoke and (optionally) a
  read-only OIDC smoke.

Deploy runner: labels `[self-hosted, linux, x64, hangar-mcp]` by default. Either
add the `hangar-mcp` label to the existing hel1 runner (the one serving
`bugit-mcp`), or set the repository variable `HANGAR_MCP_DEPLOY_RUNS_ON` to a
JSON label array such as `["self-hosted","linux","x64","bugit-mcp"]`. The
runner must be on hel1 and its user (`deploy`) needs `sudo` for `install`,
`test`, `sed`, `systemctl` and `journalctl`, like the Bugit MCP deploy. Protect
the `dumont` branch and require reviewers on the `production` environment:
anyone who can push to `dumont` and dispatch can run code on that runner.

`scripts/deploy-mcp-hel1.sh` (never prints values, only key names and status):

1. validates inputs, the archive, `/usr/bin/node` (>= 20) and pnpm;
2. stages the release and runs `pnpm install --prod --frozen-lockfile`;
3. validates the runtime configuration with the release's own
   `loadHangarConfig` (so a bad `HANGAR_WRITE_PROJECTS` fails before any
   switch) and, with introspection configured, runs the introspection
   self-check;
4. **refuses to drop keys** that the current `/etc/dumont-hangar-mcp.env` sets
   but the new file would not (prints key names; set
   `HANGAR_MCP_ALLOW_ENV_KEY_DROP=true` after reading them);
5. moves the release to `releases/<sha>-<run>`, writes the env file
   (`root:deploy 0640`, previous copy in `/etc/dumont-hangar-mcp.env.previous`,
   `root` `0600`), installs the unit, switches `current`, restarts;
6. requires `POST /mcp` on loopback to answer 401; on any failure after the
   switch it restores the previous release **and** env file and restarts.

GitHub `production` environment (names only):

| Kind     | Name                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| secret   | `HANGAR_MCP_API_KEY`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| secret   | `HANGAR_MCP_OIDC_INTROSPECTION_CLIENT_SECRET` or `HANGAR_MCP_OIDC_INTROSPECTION_PRIVATE_KEY_JSON` (only with introspection)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| secret   | `HANGAR_MCP_OIDC_SMOKE_CLIENT_ID`, `HANGAR_MCP_OIDC_SMOKE_CLIENT_SECRET` (only with `HANGAR_MCP_OIDC_SMOKE=true`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| required | `HANGAR_MCP_WORKSPACE_SLUG`, `HANGAR_MCP_ALLOWED_PROJECTS`, `HANGAR_MCP_ALLOWED_HOSTS`, `HANGAR_MCP_RESOURCE_URL`, `HANGAR_MCP_OIDC_ISSUER`, `HANGAR_MCP_OIDC_JWKS_URL`, `HANGAR_MCP_OIDC_AUDIENCE`                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| optional | `HANGAR_MCP_WRITE_PROJECTS`, `HANGAR_MCP_WRITE_RATE_LIMIT`, `HANGAR_MCP_BASE_URL`, `HANGAR_MCP_HTTP_PORT` (3014), `HANGAR_MCP_ALLOWED_ORIGINS`, `HANGAR_MCP_OIDC_READER_ROLE`, `HANGAR_MCP_OIDC_WRITER_ROLE`, `HANGAR_MCP_OIDC_REQUIRED_SCOPE`, `HANGAR_MCP_OIDC_ALLOWED_ORG_ID`, `HANGAR_MCP_OIDC_ALLOWED_SUBJECTS`, `HANGAR_MCP_OIDC_USERINFO_URL`, `HANGAR_MCP_OIDC_INTROSPECTION_URL`, `HANGAR_MCP_OIDC_INTROSPECTION_CLIENT_ID`, `HANGAR_MCP_OIDC_INTROSPECTION_{TIMEOUT_MS,CACHE_SECONDS,MAX_IN_FLIGHT,RATE_PER_SECOND}`, `HANGAR_MCP_{TIMEOUT_MS,MAX_RESPONSE_BYTES,MAX_SEARCH_PAGES,PROJECT_CACHE_SECONDS}`, `HANGAR_MCP_ALLOW_ENV_KEY_DROP` |
| repo var | `HANGAR_MCP_DEPLOY_RUNS_ON`, `HANGAR_MCP_OIDC_SMOKE`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

`HANGAR_MCP_ALLOWED_HOSTS` must include the public host and `127.0.0.1`
(current value in `.env.example`: `hangar.getdumont.ai,127.0.0.1,localhost`);
the service binds loopback and Caddy forwards the public `Host`.

Rollback on purpose: re-run the workflow from the earlier `dumont` commit, or on
the host point `current` at the previous `releases/<id>`, copy
`/etc/dumont-hangar-mcp.env.previous` back if the config changed, and restart
only `dumont-hangar-mcp.service`.

### Manual deploy (keeps the existing env file)

Use this until the workflow and its GitHub environment are set up. It keeps
`/etc/dumont-hangar-mcp.env` as is and only appends the new non-secret keys.
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
   `sudoedit` later and restart. `MCP_ALLOWED_HOSTS` must include `127.0.0.1`
   for the loopback checks below.

4. **Validate the config with the new release** before switching (secrets stay
   in the environment, never in argv or output). This sources the systemd env
   file with bash, which works for `KEY="value"` lines; if the file uses
   syntax bash reads differently, skip this step and rely on step 6:

   ```bash
   sudo bash -c 'set -a; . /etc/dumont-hangar-mcp.env; set +a; cd "$0" && node --input-type=module -e "
     const m = await import(\"./mcp/dist/config.js\");
     try { const c = m.loadHangarConfig(); m.assertHttpAuthConfigured(c);
       console.log(\"OK write projects=\" + c.writeProjects.length); }
     catch (e) { console.error(\"ERROR \" + e.message); process.exit(1); }"' "$REL"
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
