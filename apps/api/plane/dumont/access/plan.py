# Dumont addition: pure diff between ZITADEL grants and Hangar memberships.
# Not upstream Plane. No Django, no I/O: everything comes in through `Snapshot`, so every rule
# here is unit-tested without a database.
#
# Rules (see docs/dumont/zitadel-access.md):
# - Managed scopes only. The workspace is managed iff the role `hangar.workspace.member` exists in the
#   ZITADEL project; a project is managed iff any valid `hangar.project.<identifier>.*` role exists and
#   a Plane project with that identifier exists in the workspace. Everything else is left untouched.
# - Highest role wins. Grants map to Plane users through Account(provider="dumont") only.
# - Grants of ZITADEL users without a linked account are "pending" (applied at their first login).
#   An unlinked Plane member whose e-mail matches a pending grant is kept as is ("awaiting login"),
#   never removed: e-mail is only ever used to avoid a removal, never to grant anything.
# - Bots are never touched. Protected users (instance admins, the workspace owner) never lose or get
#   a lower role; they can still be granted more.
# - Project roles need an (after-plan) active workspace membership; a workspace guest is capped to
#   guest in projects (Plane invariant).
# - Deactivating a workspace membership also deactivates the user's project memberships in that
#   workspace, like Plane's own "remove member" does, so a removed user keeps no project access.
#   This cascade reaches unmanaged projects, so it only ever happens in a full sync (never per user).
# - Never leave a scope without an admin: removals/demotions that would do so are dropped.
# - Two Plane projects whose identifiers map to the same role-key part are both left unmanaged and
#   reported (`identifier_collision`); the endpoint lock still covers them when that part has roles.
# - `additive_only` (the per-user sync on login / bearer calls) keeps only changes that add access
#   (create, reactivate, role upgrade). Removals and demotions are reported as deferred and left to
#   the full sync, which has the safety brake.

from collections import defaultdict
from dataclasses import dataclass, field

from plane.dumont.access import roles as R

CREATE = "create"
REACTIVATE = "reactivate"
UPDATE_ROLE = "update_role"
DEACTIVATE = "deactivate"

WORKSPACE = "workspace"
PROJECT = "project"


@dataclass(frozen=True)
class PlaneUser:
    id: str
    email: str = ""
    is_active: bool = True
    is_bot: bool = False
    protected: bool = False  # instance admin or workspace owner
    linked: bool = False  # has an Account(provider="dumont")


@dataclass(frozen=True)
class Membership:
    role: int
    is_active: bool


@dataclass(frozen=True)
class ProjectRef:
    id: str
    identifier: str  # as stored in Plane (uppercase)

    @property
    def key_part(self):
        return R.identifier_to_key_part(self.identifier)


@dataclass(frozen=True)
class Grant:
    zitadel_user_id: str
    role_keys: tuple
    email: str | None = None
    display_name: str | None = None


@dataclass
class Snapshot:
    workspace_id: str
    workspace_slug: str
    role_keys: frozenset  # every role key that exists in the ZITADEL project
    grants: list  # [Grant], active grants only
    projects: list  # [ProjectRef] in the workspace
    accounts: dict  # zitadel sub -> plane user id
    users: dict  # plane user id -> PlaneUser (every member + every linked grantee)
    workspace_members: dict  # user id -> Membership (every non-deleted row, active or not)
    project_members: dict  # project id -> {user id -> Membership}
    only_user_ids: frozenset | None = None  # per-user sync: only plan changes for these users


@dataclass(frozen=True)
class Change:
    scope: str  # WORKSPACE or PROJECT
    scope_id: str  # workspace id or project id
    user_id: str
    action: str
    from_role: int | None
    to_role: int | None
    from_active: bool | None
    label: str = ""  # "workspace" or the project identifier, for reports
    cascade: bool = False  # consequence of a workspace-level removal/demotion

    def as_dict(self, users=None):
        user = (users or {}).get(self.user_id)
        return {
            "scope": self.label or self.scope,
            "scope_type": self.scope,
            "scope_id": self.scope_id,
            "user_id": self.user_id,
            "email": user.email if user else None,
            "action": self.action,
            "from_role": R.role_name(self.from_role) if self.from_role is not None else None,
            "to_role": R.role_name(self.to_role) if self.to_role is not None else None,
            "cascade": self.cascade,
        }


@dataclass
class Plan:
    managed_workspace: bool = False
    managed_projects: dict = field(default_factory=dict)  # project id -> identifier
    managed_identifiers: list = field(default_factory=list)  # lowercase identifiers with roles
    unknown_project_roles: list = field(default_factory=list)  # identifiers with roles but no project
    invalid_role_keys: list = field(default_factory=list)
    changes: list = field(default_factory=list)
    # additive_only: removals/demotions left for the full sync (never written by this plan)
    deferred: list = field(default_factory=list)
    pending: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    identifier_collisions: list = field(default_factory=list)
    # grants dropped at the ZITADEL organisation boundary (set by the sync, not by compute_plan)
    ignored_grants: list = field(default_factory=list)

    @property
    def deactivations(self):
        return [change for change in self.changes if change.action == DEACTIVATE]

    @property
    def cascaded(self):
        return [change for change in self.changes if change.cascade]

    @property
    def users_losing_access(self):
        """Distinct Plane users this plan deactivates or demotes anywhere (what the safety brake counts)."""
        return sorted({change.user_id for change in self.changes if reduces_access(change)})

    def note(self, kind, user_id=None, scope=None, **detail):
        entry = {"kind": kind}
        if user_id is not None:
            entry["user_id"] = user_id
        if scope is not None:
            entry["scope"] = scope
        entry.update(detail)
        self.notes.append(entry)


def reduces_access(change):
    """A deactivation or a role downgrade. Creates, reactivations and upgrades only add access."""
    if change.action == DEACTIVATE:
        return True
    return change.action == UPDATE_ROLE and (change.to_role or 0) < (change.from_role or 0)


def scopes_losing_most_members(plan, snapshot):
    """Managed scopes where the plan removes or downgrades MORE THAN HALF of the active, non-bot members.

    The relative safety brake: a small workspace can be wiped without ever crossing the absolute
    limit (DUMONT_ACCESS_MAX_REMOVALS), and that pattern is a ZITADEL-side mistake far more often
    than a decision. Returns [{"scope", "scope_id", "members", "losing"}], empty when none.
    """
    scopes = []
    if plan.managed_workspace:
        scopes.append((WORKSPACE, snapshot.workspace_id, "workspace", snapshot.workspace_members))
    for project_id, identifier in sorted(plan.managed_projects.items()):
        scopes.append((PROJECT, project_id, identifier, snapshot.project_members.get(project_id, {})))
    flagged = []
    for scope, scope_id, label, members in scopes:
        active = {
            user_id
            for user_id, membership in members.items()
            if membership.is_active and not getattr(snapshot.users.get(user_id), "is_bot", False)
        }
        losing = {
            change.user_id
            for change in plan.changes
            if change.scope == scope and change.scope_id == scope_id and reduces_access(change)
        } & active
        if active and len(losing) * 2 > len(active):
            flagged.append({"scope": label, "scope_id": scope_id, "members": len(active), "losing": len(losing)})
    return flagged


def managed_scopes(role_keys, project_identifiers):
    """Which scopes are managed, from the role keys alone.

    Returns (workspace_managed, managed identifiers (lowercase, only those with a Plane project),
    identifiers with roles but no Plane project, invalid hangar.* keys).
    """
    known = {part for part in project_identifiers if part}
    workspace_managed = R.WORKSPACE_MANAGED_MARKER in role_keys
    with_roles, invalid = set(), []
    for key in sorted(role_keys):
        if not R.is_hangar_key(key):
            continue
        parsed = R.parse_role_key(key)
        if parsed is None:
            invalid.append(key)
        elif parsed.scope == R.PROJECT_SCOPE:
            with_roles.add(parsed.identifier)
    return workspace_managed, sorted(with_roles & known), sorted(with_roles - known), invalid


def compute_plan(snapshot, additive_only=False):
    plan = Plan()
    projects_with_part = defaultdict(list)
    for project in snapshot.projects:
        part = project.key_part
        if part:
            projects_with_part[part].append(project)
    collisions = {
        part: sorted(project.identifier for project in projects)
        for part, projects in projects_with_part.items()
        if len(projects) > 1
    }
    for part, identifiers in sorted(collisions.items()):
        plan.identifier_collisions.append({"key_part": part, "identifiers": identifiers})
        plan.note("identifier_collision", scope=part, identifiers=identifiers)
    projects_by_part = {part: projects[0] for part, projects in projects_with_part.items() if part not in collisions}
    workspace_managed, managed_parts, unknown, invalid = managed_scopes(snapshot.role_keys, set(projects_with_part))
    # A part shared by two projects cannot say which one a role means: neither is managed.
    managed_parts = [part for part in managed_parts if part not in collisions]
    plan.managed_workspace = workspace_managed
    plan.managed_identifiers = managed_parts
    plan.unknown_project_roles = unknown
    plan.invalid_role_keys = invalid
    plan.managed_projects = {projects_by_part[part].id: projects_by_part[part].identifier for part in managed_parts}
    project_by_id = {project.id: project for project in snapshot.projects}

    desired_ws, desired_projects, pending_emails = _desired(snapshot, plan, projects_by_part, managed_parts)

    def in_scope(user_id):
        return snapshot.only_user_ids is None or user_id in snapshot.only_user_ids

    # --- workspace ---------------------------------------------------------------------------
    ws_changes = []
    if workspace_managed:
        ws_changes = _scope_changes(
            plan,
            snapshot,
            scope=WORKSPACE,
            scope_id=snapshot.workspace_id,
            label="workspace",
            actual=snapshot.workspace_members,
            desired=desired_ws,
            pending_emails=pending_emails,
            in_scope=in_scope,
        )
        ws_changes = _keep_an_admin(plan, WORKSPACE, "workspace", snapshot.workspace_members, ws_changes)
    plan.changes.extend(ws_changes)
    final_ws = _final_state(snapshot.workspace_members, ws_changes)

    # --- managed projects ----------------------------------------------------------------------
    managed_project_ids = set(plan.managed_projects)
    for project_id in sorted(managed_project_ids):
        project = project_by_id[project_id]
        desired = {}
        for user_id, role in desired_projects.get(project_id, {}).items():
            ws_role = final_ws.get(user_id)
            if ws_role is None:
                if in_scope(user_id):
                    plan.note("no_workspace_membership", user_id, project.identifier, role=R.role_name(role))
                continue
            if ws_role == R.GUEST and role > R.GUEST:
                if in_scope(user_id):
                    plan.note("capped_to_guest", user_id, project.identifier, granted=R.role_name(role))
                role = R.GUEST
            desired[user_id] = role
        actual = snapshot.project_members.get(project_id, {})
        changes = _scope_changes(
            plan,
            snapshot,
            scope=PROJECT,
            scope_id=project_id,
            label=project.identifier,
            actual=actual,
            desired=desired,
            pending_emails=pending_emails,
            in_scope=in_scope,
        )
        plan.changes.extend(_keep_an_admin(plan, PROJECT, project.identifier, actual, changes))

    # --- cascade of workspace removals / demotions into unmanaged projects --------------------
    # Full sync only: it reaches projects ZITADEL does not manage, so it stays behind the brake.
    if workspace_managed and not additive_only:
        plan.changes.extend(_cascade(plan, snapshot, ws_changes, managed_project_ids, project_by_id))

    if additive_only:
        # Everything above was planned as if the whole plan applied (so a project role is never granted
        # on a workspace membership that the full sync is about to remove); only the additions are kept.
        plan.deferred = [change for change in plan.changes if reduces_access(change)]
        plan.changes = [change for change in plan.changes if not reduces_access(change)]
    return plan


def _desired(snapshot, plan, projects_by_part, managed_parts):
    """Aggregate grants into desired roles per Plane user; record pending grants."""
    desired_ws = {}
    desired_projects = defaultdict(dict)
    pending_emails = set()
    managed_parts = set(managed_parts)
    for grant in snapshot.grants:
        ws_role, project_roles = None, {}
        for key in grant.role_keys:
            parsed = R.parse_role_key(key)
            if parsed is None:
                continue
            if parsed.scope == R.WORKSPACE_SCOPE:
                if plan.managed_workspace:
                    ws_role = max(ws_role or 0, parsed.role)
            elif parsed.identifier in managed_parts:
                project_id = projects_by_part[parsed.identifier].id
                project_roles[project_id] = max(project_roles.get(project_id, 0), parsed.role)
        if ws_role is None and not project_roles:
            continue
        user_id = snapshot.accounts.get(grant.zitadel_user_id)
        if user_id is None:
            plan.pending.append(
                {
                    "zitadel_user_id": grant.zitadel_user_id,
                    "email": grant.email,
                    "display_name": grant.display_name,
                    "roles": sorted(key for key in grant.role_keys if R.parse_role_key(key) is not None),
                }
            )
            if grant.email:
                pending_emails.add(grant.email.strip().lower())
            continue
        user = snapshot.users.get(user_id)
        if user is not None and user.is_bot:
            plan.note("bot_grant_ignored", user_id)
            continue
        if ws_role is not None:
            desired_ws[user_id] = max(desired_ws.get(user_id, 0), ws_role)
        for project_id, role in project_roles.items():
            desired_projects[project_id][user_id] = max(desired_projects[project_id].get(user_id, 0), role)
    return desired_ws, desired_projects, pending_emails


def _scope_changes(plan, snapshot, *, scope, scope_id, label, actual, desired, pending_emails, in_scope):
    changes = []
    for user_id in sorted(set(actual) | set(desired)):
        if not in_scope(user_id):
            continue
        user = snapshot.users.get(user_id) or PlaneUser(id=user_id)
        if user.is_bot:
            continue
        current = actual.get(user_id)
        want = desired.get(user_id)

        def make(action, to_role, _current=current, _user_id=user_id):
            return Change(
                scope=scope,
                scope_id=scope_id,
                user_id=_user_id,
                action=action,
                from_role=_current.role if _current else None,
                to_role=to_role,
                from_active=_current.is_active if _current else None,
                label=label,
            )

        if want is None:
            if current is None or not current.is_active:
                continue
            if not user.linked and user.email and user.email.strip().lower() in pending_emails:
                plan.note("awaiting_dumont_login", user_id, label)
                continue
            if user.protected:
                plan.note("protected_kept", user_id, label, role=R.role_name(current.role))
                continue
            changes.append(make(DEACTIVATE, None))
            continue

        if not user.is_active:
            # A deactivated Plane user gets nothing new; existing rows are left for Plane to handle.
            if current is None or not current.is_active or current.role != want:
                plan.note("plane_user_inactive", user_id, label)
            continue
        if current is None:
            changes.append(make(CREATE, want))
        elif not current.is_active:
            changes.append(make(REACTIVATE, want))
        elif current.role != want:
            if want < current.role and user.protected:
                plan.note("protected_kept", user_id, label, role=R.role_name(current.role))
                continue
            changes.append(make(UPDATE_ROLE, want))
    return changes


def _final_state(actual, changes):
    """user id -> role of the ACTIVE memberships after applying `changes` to `actual`."""
    state = {user_id: m.role for user_id, m in actual.items() if m.is_active}
    for change in changes:
        if change.action == DEACTIVATE:
            state.pop(change.user_id, None)
        else:
            state[change.user_id] = change.to_role
    return state


def _keep_an_admin(plan, scope, label, actual, changes):
    """Drop removals/demotions of current admins when the scope would end up without any admin."""
    had_admin = any(m.is_active and m.role == R.ADMIN for m in actual.values())
    if not had_admin:
        return changes
    final = _final_state(actual, changes)
    if any(role == R.ADMIN for role in final.values()):
        return changes
    kept = []
    for change in changes:
        current = actual.get(change.user_id)
        losing_admin = (
            current is not None
            and current.is_active
            and current.role == R.ADMIN
            and (change.action == DEACTIVATE or (change.to_role or 0) < R.ADMIN)
        )
        if losing_admin:
            plan.note("last_admin_kept", change.user_id, label, action=change.action)
            continue
        kept.append(change)
    return kept


def _cascade(plan, snapshot, ws_changes, managed_project_ids, project_by_id):
    """Mirror Plane: a workspace removal deactivates the user's projects; a guest is guest everywhere."""
    removed = {c.user_id for c in ws_changes if c.action == DEACTIVATE}
    demoted_to_guest = {
        c.user_id for c in ws_changes if c.action in (UPDATE_ROLE, REACTIVATE, CREATE) and c.to_role == R.GUEST
    }
    if not removed and not demoted_to_guest:
        return []
    changes = []
    for project_id in sorted(snapshot.project_members):
        if project_id in managed_project_ids or project_id not in project_by_id:
            continue  # managed projects were planned above from their own grants
        label = project_by_id[project_id].identifier
        actual = snapshot.project_members[project_id]
        project_changes = []
        for user_id in sorted(removed | demoted_to_guest):
            current = actual.get(user_id)
            if current is None or not current.is_active:
                continue
            common = dict(
                scope=PROJECT,
                scope_id=project_id,
                user_id=user_id,
                from_role=current.role,
                from_active=True,
                label=label,
                cascade=True,
            )
            if user_id in removed:
                project_changes.append(Change(action=DEACTIVATE, to_role=None, **common))
            elif current.role > R.GUEST:
                project_changes.append(Change(action=UPDATE_ROLE, to_role=R.GUEST, **common))
        changes.extend(_keep_an_admin(plan, PROJECT, label, actual, project_changes))
    return changes
