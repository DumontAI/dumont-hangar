# Hangar MCP server

Read-only MCP server for the Dumont Hangar (Plane) instance. It exposes Hangar
projects, work items, comments, states, labels and members to MCP clients
without ever forwarding the caller's credential to Hangar: upstream reads use a
server-side Hangar API token.

Only **Streamable HTTP** (`dist/http.js`) is supported, behind ZITADEL OIDC.
The earlier API-key/stdio launcher and static MCP bearer mode are retired.

## Tools (read-only)

| Tool                             | Purpose                                                                    |
| -------------------------------- | -------------------------------------------------------------------------- |
| `hangar_list_projects`           | Projects in the server allowlist                                           |
| `hangar_get_project`             | One project by identifier or UUID                                          |
| `hangar_list_work_items`         | Work items of a project, with state/assignee/label/priority/search filters |
| `hangar_get_work_item`           | One work item by `HGR-5` or UUID                                           |
| `hangar_search_work_items`       | Text search, one project or the whole allowlist                            |
| `hangar_list_work_item_comments` | Comments of a work item                                                    |
| `hangar_list_states`             | Workflow states of a project                                               |
| `hangar_list_labels`             | Labels of a project                                                        |
| `hangar_list_members`            | Workspace or project members (no emails)                                   |

Every tool is annotated read-only and non-destructive. Project access is limited
by `HANGAR_ALLOWED_PROJECTS`; text fields are credential-scrubbed before they
leave the server.

## Configuration

See [.env.example](.env.example). The important ones:

| Variable                   | Meaning                                              |
| -------------------------- | ---------------------------------------------------- |
| `HANGAR_BASE_URL`          | Hangar origin, default `https://hangar.getdumont.ai` |
| `HANGAR_API_KEY`           | Dedicated Hangar bot token. Server-side only         |
| `HANGAR_WORKSPACE_SLUG`    | Workspace slug                                       |
| `HANGAR_ALLOWED_PROJECTS`  | CSV of identifiers (`HGR`) or project UUIDs          |
| `MCP_AUTH_MODE`            | `oidc` only                                          |
| `MCP_RESOURCE_URL`         | Public MCP URL, `https://hangar.getdumont.ai/mcp`    |
| `MCP_OIDC_AUDIENCE`        | ZITADEL project audience (the `ZITADEL DCR` project) |
| `MCP_OIDC_REQUIRED_ROLE`   | `hangar_reader`                                      |
| `MCP_OIDC_INTROSPECTION_*` | Optional RFC 7662 introspection for opaque tokens    |

## Team access with login

Point compatible clients at `https://hangar.getdumont.ai/mcp` and pin the
pre-registered public client (`392047847798800387`, redirect
`http://127.0.0.1:19876/mcp/oauth/callback`, PKCE, no secret). The client opens
the Dumont login; the token must carry `hangar_reader`. Do not let the client
self-register through ZITADEL DCR: those applications receive opaque (JWE)
access tokens, which only work when the introspection credentials are
configured.

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
  symlink `/opt/dumont-hangar-mcp/current`.
- `dumont-hangar-mcp.service` runs `dist/http.js` on `127.0.0.1:3014` as
  `deploy`, reading `/etc/dumont-hangar-mcp.env` (mode `0640`).
- Caddy on `hangar.getdumont.ai` routes `/mcp` and the protected-resource
  metadata paths to `127.0.0.1:3014`; everything else stays with the Hangar
  stack.
- Deploy a tested `mcp/` build as a new release directory, switch `current`,
  restart only `dumont-hangar-mcp.service`, then verify the OIDC challenge and
  an authenticated read. Keep the previous release for rollback.

The historical downloadable `/hangar-mcp` launcher is disabled. Older local
copies cannot be disabled by a server release: remove their MCP registrations
and revoke their personal Hangar tokens only after confirming no other API use.
