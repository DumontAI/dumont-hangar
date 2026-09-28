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
- **Managed**: the workspace is managed once the role `hangar.workspace.member` exists. A project is managed once any `hangar.project.<identifier>.*` role exists and a Hangar project with that identifier exists. Only projects whose identifier is plain ASCII `a-z 0-9 _` (up to 12 characters, checked before lowercasing) can be managed. The export lists the others as skipped. If two projects map to the same key part, neither is managed: the sync reports `identifier_collision`, and when that part has roles the endpoint lock still covers both.
- **Unmanaged** scopes are never touched, with one exception described in the rules below.

## What the sync does

For every managed scope it creates, reactivates, changes the role of, or deactivates the `WorkspaceMember` / `ProjectMember` rows so that they match the grants. Removal means `is_active=False`, exactly like Plane's own "remove member". Rows are never hard-deleted.

- **When it runs**
  - A full sync every 5 minutes (Celery beat, `plane.dumont.access.tasks.dumont_access_full_sync`), and on demand with `python manage.py dumont_access_sync`. Only the full sync removes or reduces access.
  - A per-user sync right after a Dumont web login, and on API v1 calls made with a ZITADEL bearer token. The bearer case runs at most once per 60 s per user. The per-user sync only **adds** access: it creates, reactivates and upgrades memberships. A removal or demotion it sees is reported as `deferred_to_full_sync` and left to the next full sync, which has the safety brake. It never cascades into other projects. After any ZITADEL error both hooks skip ZITADEL for 60 s (cache flag `dumont_access:zitadel_backoff`), so an outage does not slow down every login and API call.
- **Organisation boundary**: the ZITADEL instance is shared with other products, so only the Dumont organisation (`DUMONT_ZITADEL_ORG_ID`, the same variable the bearer auth uses) counts. Every search is sent with `x-zitadel-orgid`, and a grant is also ignored when:
  - it came through a project grant to another organisation (`projectGrantId` set);
  - its `orgId` or `details.resourceOwner` names another organisation;
  - its user is not a user of the Dumont organisation. This is checked with an org-scoped `POST /management/v1/users/_search` (`inUserIdsQuery`).

  Ignored grants are listed in the report under `ignored_grants` (ZITADEL user id and reason, no e-mail) and logged as a warning. A per-user sync for a login whose ZITADEL user is not in the Dumont organisation changes nothing and reports `skipped`. With `DUMONT_ZITADEL_ORG_ID` set, the web login refuses such users anyway (see "Web login organisation check").
- **Fail safe on odd answers**: a search answer without a `result` field counts as an empty list only when `details` is present and its `totalResult` is absent or 0 (ZITADEL's JSON gateway may omit empty lists and zero numbers). Any other answer without a `result` list is an error, and so are an empty page while `totalResult` says more rows exist, and grants whose users the org-scoped `users/_search` returns none of (a silently filtered HTTP 200) are all errors. The run writes nothing.
- **Identity**: a grant maps to a Hangar user only through `Account(provider="dumont", provider_account_id=<ZITADEL user id>)`, which is created at the user's first Dumont login. There is no match by e-mail. A Hangar user can have several Dumont accounts (Plane links a second ZITADEL user with the same verified e-mail to the same Hangar user); the grants of all of them count, in the full sync and in the per-user sync.
- **Pending**: a grant for someone who has never signed in with Dumont is reported as pending. It is applied at that user's first Dumont login. That first login must be allowed to create the Hangar user. With sign-up disabled (`ENABLE_SIGNUP` = `0` in the instance configuration, which falls back to the environment variable), Plane refuses the login with `SIGNUP_DISABLED` unless the person already has a Hangar user or a workspace invitation for that e-mail exists. In `enforce`, invitations to a managed workspace are locked, so with sign-up off a grant-only person cannot get in at all until sign-up is enabled or someone creates the Hangar user. The sync does not change that rule. Check the production value before relying on grants alone.
- **Awaiting login**: a Hangar member without a Dumont login whose e-mail equals the e-mail on a pending grant is left as is. The member is not removed and the role is not changed. E-mail is only ever used to avoid a removal, never to grant anything.
- **Never touched**
  - Bots.
  - Instance admins and the workspace owner. They can gain roles, but the sync never removes or demotes them. This is the break-glass path.
  - The last admin of a scope. A removal or demotion that would leave a workspace or project without an admin is skipped and reported (`last_admin_kept`).
- **Plane invariants**
  - A project role needs an active workspace membership (`no_workspace_membership` in the report).
  - A workspace guest is at most a guest in projects (`capped_to_guest`).
  - Removing someone from a managed workspace (or making them a workspace guest) also deactivates (or caps to guest) their project memberships in that workspace, including unmanaged projects. This is what Plane's own "remove member" does, so a removed user keeps no access through old project rows. It is the one exception to "unmanaged is untouched", and it only happens in a full sync. Every cascaded row is logged at WARNING (`dumont access: cascade ...`, with project identifier, project id and user id) and listed in the report under `cascaded`.
- **Fail safe**: if the configuration is incomplete, or ZITADEL is unreachable or answers an error, nothing is written and the previous state stays. The failure is logged.
- **Required configuration**: in `dry-run` and `enforce`, every run checks `DUMONT_ACCESS_WORKSPACE_SLUG`, `DUMONT_ACCESS_ZITADEL_PROJECT_ID`, `DUMONT_ZITADEL_ORG_ID` and `DUMONT_ACCESS_ZITADEL_KEY_JSON` before it calls ZITADEL. If one is missing, the run stops with an error that names it. `manage.py dumont_access_sync` exits 1, and the beat logs the error every 5 minutes. In `enforce`, the lock then answers 503 instead of letting changes through. There is no fallback organisation, because the instance is shared.
- **Safety brake**: in `enforce`, a full sync that would remove or reduce the access of more than `DUMONT_ACCESS_MAX_REMOVALS` distinct users (default 5) writes nothing and logs `SAFETY BRAKE` at critical level. It counts people, not rows: a deactivation or a role downgrade anywhere, cascades included, counts once per user. A mass removal is far more likely a ZITADEL mistake than a real decision: a wrong project id, a lost permission, or an empty answer. Review with `--mode dry-run`. If the removals are real, run once with `python manage.py dumont_access_sync --max-removals N`; the override applies to that run only.
- **Concurrency**: every row is re-checked under a row lock before it is written. If a row changed since the plan was made, it is skipped as `stale` and the next run plans it again. Within a scope, additions are written before removals, and removing or demoting an admin locks the scope's other active admin rows first: if none is left, that change is skipped as `stale` too.

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
- Deleting a project is not locked. Plane's usual permission applies (workspace admin or project admin). Deleting a managed project removes it from management, and its `hangar.project.<id>.*` roles then show up under `unknown_project_roles`.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `DUMONT_ACCESS_SYNC` | `off` | `off` \| `dry-run` \| `enforce` |
| `DUMONT_ACCESS_WORKSPACE_SLUG` | — | e.g. `dumont` |
| `DUMONT_ACCESS_ZITADEL_PROJECT_ID` | — | Project that holds the roles (the MCP audience project) |
| `DUMONT_ZITADEL_ORG_ID` | — | The Dumont organisation, shared with the bearer auth (`plane/dumont/auth`) and the web login check: one value governs all three. Bare id (no `:` or whitespace). Sent as `x-zitadel-orgid`. Only grants and users of this org count. Required in `dry-run` and `enforce` |
| `DUMONT_ACCESS_ZITADEL_KEY_JSON` | — | The service user's JSON key: the file's content or a path to it. Secret, so keep it in the vault, never in git |
| `DUMONT_ACCESS_MAX_REMOVALS` | `5` | Safety brake of the full sync: distinct users losing or reducing access. `--max-removals N` overrides it for one manual run |
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
  - `PROJECT_OWNER_VIEWER`, granted on this one project only. It is narrower, and it may not be allowed to read users. ZITADEL does not always answer that with a 403: a search can also come back **HTTP 200 with the rows filtered out** by permission. The sync treats "grants exist but `users/_search` returns none of their users" as an error and writes nothing, but a partial filter (some users visible, others not) cannot be told apart from those users being outside the organisation: their grants would be dropped as `user_outside_org`, which in `enforce` means removals. Prefer `ORG_OWNER_VIEWER`, and read `ignored_grants` in the dry-run before `enforce`.

  Avoid `ORG_USER_MANAGER` and the `*_OWNER` roles, because they can write. **Not verified:** which viewer role includes reading user grants (`user.grant.read`) on the ZITADEL version in production. Test it with a dry-run: a 403 from `users/grants/_search` means the role is too narrow. The sync then writes nothing and reports `error`. A role that silently filters grants would instead show up in the dry-run as unexpected removals (or pending grants), which is why the dry-run step comes before `enforce`.
- No write permission. The sync never writes to ZITADEL.

The bootstrap script is the only thing that writes. It uses a separate admin Personal Access Token (`ZITADEL_ADMIN_PAT`), passed only in the environment of that one run.

## Web login organisation check

The Dumont web login (`apps/api/plane/authentication/provider/oauth/dumont.py`) asks ZITADEL for the scope `urn:zitadel:iam:user:resourceowner`, which adds the claim `urn:zitadel:iam:user:resourceowner:id` (the user's organisation) to the userinfo answer.

- `DUMONT_ZITADEL_ORG_ID` **unset**: no check. Any ZITADEL user of the shared instance can sign in, as before.
- `DUMONT_ZITADEL_ORG_ID` **set**: the login is refused with `DUMONT_ORG_NOT_ALLOWED` (5116) unless the claim equals it. A missing claim is refused too. The check runs before Hangar looks up the user, so a refused login never creates a user, never links a Dumont account and never matches an existing user by e-mail.
- A malformed value (with `:` or whitespace) refuses every Dumont login with `DUMONT_NOT_CONFIGURED`, instead of silently turning the check off.

The claim is read from userinfo, which Hangar fetches from the issuer with the access token. The unverified `id_token` is not used.

## Rollout

0. **Web login check first**: set `DUMONT_ZITADEL_ORG_ID`, restart the API, and do one Dumont login with a user of the Dumont organisation. It must land in Hangar. If it fails with `DUMONT_ORG_NOT_ALLOWED`, the id is wrong or ZITADEL does not return the claim: unset the variable (login works as before) and check. The API log line `Dumont login refused: user is not in the configured ZITADEL organization` marks a refusal.
1. **Deploy with `DUMONT_ACCESS_SYNC=off`.** Nothing changes.
2. **Export current access**: `python manage.py dumont_access_export --output /tmp/hangar-access.json` (add `--format csv` to review it in a spreadsheet). Users without a Dumont login are flagged `no Dumont login yet`. The export skips bots and projects whose identifier cannot be a role key.
3. **Bootstrap ZITADEL, with the sync still `off`**:
   `ZITADEL_ADMIN_PAT=… scripts/dumont/zitadel_access_bootstrap.py /tmp/hangar-access.json --zitadel-url https://auth.getdumont.ai --project-id … --org-id …`
   This prints the plan and writes nothing. When the plan is right, run it again with `--apply --yes`; it prints the plan it is applying before it writes. The script only adds: it creates missing roles and adds missing keys to grants, keeping other keys such as `hangar_reader`. Right before each grant update it re-reads the grant and writes the union of its current keys and the new ones. It never removes anything and is idempotent. Users without a Dumont login are resolved by e-mail: the match must be owned by the Dumont organisation (`details.resourceOwner`) and have a verified e-mail; with zero, several or unverified matches they are skipped and listed. `--org-id` defaults to `DUMONT_ZITADEL_ORG_ID`. A Dumont login that belongs to another organisation is skipped and listed as well, and a grant owned by another organisation is never updated. Use `--projects mo,hgr` and `--skip-workspace` to manage scopes one at a time.
4. **Set `DUMONT_ACCESS_SYNC=dry-run`** and read the report: `python manage.py dumont_access_sync --mode dry-run` (or `--json`). Expect no removals for people who should keep access. Check `pending`, `notes`, `ignored_grants`, `cascaded`, `identifier_collisions` and `unknown_project_roles`. Every 5 minutes the beat also logs a one-line summary. Check `ENABLE_SIGNUP` if some people only have grants (see "Pending").
5. **Set `DUMONT_ACCESS_SYNC=enforce`.** Memberships now follow ZITADEL and the endpoints are locked.

## Rollback

Set `DUMONT_ACCESS_SYNC=off` and restart the API and worker containers. The sync stops, the per-user hooks stop, and the endpoint lock disappears at once. Memberships stay as they are, and Plane manages them again.

To take a single project out of management, delete its `hangar.project.<id>.*` roles in ZITADEL. The same works for the workspace: delete `hangar.workspace.member`.

To undo the web login check, unset `DUMONT_ZITADEL_ORG_ID` and restart the API. Note that the bearer auth requires that variable while `DUMONT_API_BEARER_ENABLED=1`.

**Nothing is reverted automatically.** Turning the sync off, or fixing a wrong grant, does not bring back memberships the sync already deactivated or demoted. That includes the cascade into unmanaged projects: those projects have no grants that a later sync could restore from. To restore:

- Find the rows: every cascaded row is a WARNING log line `dumont access: cascade applied: <action> project=<identifier> project_id=<id> user_id=<id> role <from>-><to>`, and the `--json` report of a manual run lists them under `cascaded` (all removals are under `changes`).
- Managed scopes: fix the grant in ZITADEL; the next sync reactivates the rows.
- Unmanaged projects: re-add the person in Hangar (project members, with the role from the log line), or reactivate the rows in `python manage.py shell`:
  `ProjectMember.objects.filter(project_id="<project_id>", member_id="<user_id>").update(is_active=True, role=<from role number>)` (admin 20, member 15, guest 5).
