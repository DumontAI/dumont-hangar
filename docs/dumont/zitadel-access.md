# Hangar access managed in Dumont Auth (ZITADEL)

Operator notes for the membership sync in `apps/api/plane/dumont/access/`. Dumont addition, not upstream Plane.

When the sync is on, workspace and project memberships in Hangar are a copy of the user grants in ZITADEL. ZITADEL decides who is in, and Hangar follows. That holds only for managed scopes; everything else keeps working the usual Plane way.

## Role scheme

All roles live in one ZITADEL project, `DUMONT_ACCESS_ZITADEL_PROJECT_ID`. It is the same project that holds the MCP roles (the MCP audience).

| Role key | Meaning |
|---|---|
| `hangar.workspace.admin` / `.member` / `.guest` | Membership of the workspace `DUMONT_ACCESS_WORKSPACE_SLUG` |
| `hangar.project.<identifier>.admin` / `.member` / `.guest` | Membership of the project with that identifier, in lowercase. Example: `hangar.project.mo.member` for project `MO` |

- If a user holds several roles for the same scope, the highest wins: admin (20) > member (15) > guest (5).
- `hangar_reader` and `hangar_writer` are gates for the MCP and API. They are not memberships, and the sync ignores them.
- **Managed**: the workspace is managed once the role `hangar.workspace.member` exists. A project is managed once any `hangar.project.<identifier>.*` role exists and a Hangar project with that identifier exists. Only projects whose identifier is `a-z 0-9 _` (up to 12 characters) can be managed. The export lists the others as skipped.
- **Unmanaged** scopes are never touched, with one exception described in the rules below.

## What the sync does

For every managed scope it creates, reactivates, changes the role of, or deactivates the `WorkspaceMember` / `ProjectMember` rows so that they match the grants. Removal means `is_active=False`, exactly like Plane's own "remove member". Rows are never hard-deleted.

- **When it runs**
  - A full sync every 5 minutes (Celery beat, `plane.dumont.access.tasks.dumont_access_full_sync`), and on demand with `python manage.py dumont_access_sync`.
  - A per-user sync right after a Dumont web login, and on API v1 calls made with a ZITADEL bearer token. The bearer case runs at most once per 60 s per user.
- **Organisation boundary**: the ZITADEL instance is shared with other products, so only the Dumont organisation (`DUMONT_ACCESS_ZITADEL_ORG_ID`) counts. Every search is sent with `x-zitadel-orgid`, and a grant is also ignored when:
  - it came through a project grant to another organisation (`projectGrantId` set);
  - its `orgId` or `details.resourceOwner` names another organisation;
  - its user is not a user of the Dumont organisation. This is checked with an org-scoped `POST /management/v1/users/_search` (`inUserIdsQuery`).

  Ignored grants are listed in the report under `ignored_grants` (ZITADEL user id and reason, no e-mail) and logged as a warning. Someone who signs in to Hangar with an account of another organisation gets no membership from ZITADEL, and in managed scopes loses what they had.
- **Identity**: a grant maps to a Hangar user only through `Account(provider="dumont", provider_account_id=<ZITADEL user id>)`, which is created at the user's first Dumont login. There is no match by e-mail.
- **Pending**: a grant for someone who has never signed in with Dumont is reported as pending. It is applied at that user's first Dumont login.
- **Awaiting login**: a Hangar member without a Dumont login whose e-mail equals the e-mail on a pending grant is left as is. The member is not removed and the role is not changed. E-mail is only ever used to avoid a removal, never to grant anything.
- **Never touched**
  - Bots.
  - Instance admins and the workspace owner. They can gain roles, but the sync never removes or demotes them. This is the break-glass path.
  - The last admin of a scope. A removal or demotion that would leave a workspace or project without an admin is skipped and reported (`last_admin_kept`).
- **Plane invariants**
  - A project role needs an active workspace membership (`no_workspace_membership` in the report).
  - A workspace guest is at most a guest in projects (`capped_to_guest`).
  - Removing someone from a managed workspace also deactivates their project memberships in that workspace, including unmanaged projects. This is what Plane's own "remove member" does, so a removed user keeps no access through old project rows. It is the one exception to "unmanaged is untouched".
- **Fail safe**: if the configuration is incomplete, or ZITADEL is unreachable or answers an error, nothing is written and the previous state stays. The failure is logged.
- **Required configuration**: in `dry-run` and `enforce`, every run checks `DUMONT_ACCESS_WORKSPACE_SLUG`, `DUMONT_ACCESS_ZITADEL_PROJECT_ID`, `DUMONT_ACCESS_ZITADEL_ORG_ID` and `DUMONT_ACCESS_ZITADEL_KEY_JSON` before it calls ZITADEL. If one is missing, the run stops with an error that names it. `manage.py dumont_access_sync` exits 1, and the beat logs the error every 5 minutes. In `enforce`, the lock then answers 503 instead of letting changes through. There is no fallback organisation, because the instance is shared.
- **Safety brake**: in `enforce`, a full sync that would deactivate more than `DUMONT_ACCESS_MAX_REMOVALS` memberships (default 5) writes nothing and logs `SAFETY BRAKE` at critical level. A mass removal is far more likely a ZITADEL mistake than a real decision: a wrong project id, a lost permission, or an empty answer. Review with `--mode dry-run`. If the removals are real, raise the limit for one run.
- **Concurrency**: every row is re-checked under a row lock before it is written. If a row changed since the plan was made, it is skipped as `stale` and the next run plans it again.

### Locked endpoints (enforce only)

On managed scopes, every HTTP path that changes membership answers 403 with `{"error_code": "DUMONT_MANAGED_BY_ZITADEL", "error": "... Ask for role hangar.project.<id>.<role>."}`. That covers adding, changing, removing, leaving, inviting, accepting invites, and joining projects. It applies to the web app and to API v1. The owner cannot leave on their own either: ZITADEL decides.

- A PATCH that only touches personal preferences (`view_props`, `default_props`, `preferences`, `sort_order`, and the like) stays allowed.
- Renaming the identifier of a managed project is also refused, because the rename would silently take the project out of management.
- The lock reads the managed scopes that the last sync cached. On a cache miss it asks ZITADEL once. If that also fails, membership changes in the configured workspace answer 503 `DUMONT_ACCESS_STATE_UNAVAILABLE` instead of guessing.

Creating a project is still allowed, because roles may be prepared in ZITADEL before the project exists. Plane makes the creator admin of the new project. When the new identifier already has roles in ZITADEL, in `enforce`:

- Naming a different project lead is refused with 403 `DUMONT_MANAGED_BY_ZITADEL`, because Plane would make that person admin too.
- After the create, a full sync is queued at once. It does not wait for the next beat. The creator keeps the admin row only while no ZITADEL admin of that project exists (last-admin rule).

Renaming an unmanaged project to an identifier that already has roles works the same way as creating one: the next sync brings its members in line.

Paths that change memberships outside HTTP requests are not locked:

- Operator commands `create_project_member` and `reactivate_workspace_member`. Run them only when you mean it; the next sync reverts them on managed scopes.
- Pending invitations accepted earlier are turned into memberships at login (`process_workspace_project_invitations`). A Dumont login runs the per-user sync right after that, so the result is corrected immediately. A login by another method is corrected by the next full sync.
- A user deleting their own account deactivates all their memberships. The sync does not re-grant a deactivated Plane user.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `DUMONT_ACCESS_SYNC` | `off` | `off` \| `dry-run` \| `enforce` |
| `DUMONT_ACCESS_WORKSPACE_SLUG` | — | e.g. `dumont` |
| `DUMONT_ACCESS_ZITADEL_PROJECT_ID` | — | Project that holds the roles (the MCP audience project) |
| `DUMONT_ACCESS_ZITADEL_ORG_ID` | — | The Dumont organisation. Sent as `x-zitadel-orgid`. Only grants and users of this org count. Required in `dry-run` and `enforce` |
| `DUMONT_ACCESS_ZITADEL_KEY_JSON` | — | The service user's JSON key: the file's content or a path to it. Secret, so keep it in the vault, never in git |
| `DUMONT_ACCESS_MAX_REMOVALS` | `5` | Safety brake of the full sync |
| `DUMONT_AUTH_HOST` | `https://auth.getdumont.ai` | Shared with the web login |

## What the ZITADEL service user needs

Least privilege, and read-only:

- A **service user** (machine user) with a **JSON key**. The sync signs a JWT with the key and exchanges it with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and `scope=openid urn:zitadel:iam:org:project:id:zitadel:aud`.
- A **read-only** manager role on the organisation that owns the project, so it can call:
  - `POST /management/v1/projects/{id}/roles/_search`
  - `POST /management/v1/users/grants/_search`
  - `POST /management/v1/users/_search` (only to check that grantees are users of the Dumont organisation)

  Two candidates:
  - `ORG_OWNER_VIEWER`, read-only on the Dumont organisation. It should cover all three calls.
  - `PROJECT_OWNER_VIEWER`, granted on this one project only. It is narrower, but probably cannot read users, and then the sync stops with an error on `users/_search` and writes nothing.

  Avoid `ORG_USER_MANAGER` and the `*_OWNER` roles, because they can write. **Not verified:** which viewer role includes reading user grants (`user.grant.read`) on the ZITADEL version in production. Test it with a dry-run: a 403 from `users/grants/_search` means the role is too narrow. The sync then writes nothing and reports `error`. A role that silently filters grants would instead show up in the dry-run as unexpected removals, which is why the dry-run step comes before `enforce`.
- No write permission. The sync never writes to ZITADEL.

The bootstrap script is the only thing that writes. It uses a separate admin Personal Access Token (`ZITADEL_ADMIN_PAT`), passed only in the environment of that one run.

## Rollout

1. **Deploy with `DUMONT_ACCESS_SYNC=off`.** Nothing changes.
2. **Export current access**: `python manage.py dumont_access_export --output /tmp/hangar-access.json` (add `--format csv` to review it in a spreadsheet). Users without a Dumont login are flagged `no Dumont login yet`. The export skips bots and projects whose identifier cannot be a role key.
3. **Bootstrap ZITADEL, with the sync still `off`**:
   `ZITADEL_ADMIN_PAT=… scripts/dumont/zitadel_access_bootstrap.py /tmp/hangar-access.json --zitadel-url https://auth.getdumont.ai --project-id … --org-id …`
   This prints the plan and writes nothing. When the plan is right, run it again with `--apply --yes`. The script only adds: it creates missing roles and adds missing keys to grants, keeping other keys such as `hangar_reader`. It never removes anything and is idempotent. Users without a Dumont login are resolved by e-mail inside the Dumont organisation; with zero or several matches they are skipped and listed. A Dumont login that belongs to another organisation is skipped and listed as well, and a grant owned by another organisation is never updated. Use `--projects mo,hgr` and `--skip-workspace` to manage scopes one at a time.
4. **Set `DUMONT_ACCESS_SYNC=dry-run`** and read the report: `python manage.py dumont_access_sync --mode dry-run` (or `--json`). Expect no removals for people who should keep access. Check `pending`, `notes` and `unknown_project_roles`. Every 5 minutes the beat also logs a one-line summary.
5. **Set `DUMONT_ACCESS_SYNC=enforce`.** Memberships now follow ZITADEL and the endpoints are locked.

## Rollback

Set `DUMONT_ACCESS_SYNC=off` and restart the API and worker containers. The sync stops, the per-user hooks stop, and the endpoint lock disappears at once. Memberships stay as they are, and Plane manages them again.

To take a single project out of management, delete its `hangar.project.<id>.*` roles in ZITADEL. The same works for the workspace: delete `hangar.workspace.member`.
