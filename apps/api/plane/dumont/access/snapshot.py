# Dumont addition: read the Plane side of the membership sync into a plan.Snapshot.
# Not upstream Plane. Read-only.

from plane.db.models import Account, Project, ProjectMember, User, Workspace, WorkspaceMember
from plane.dumont.access.plan import Grant, Membership, PlaneUser, ProjectRef, Snapshot
from plane.license.models import InstanceAdmin

DUMONT_PROVIDER = "dumont"


class WorkspaceNotFound(Exception):
    pass


def load_workspace(slug):
    workspace = Workspace.objects.filter(slug=slug).first()
    if workspace is None:
        raise WorkspaceNotFound(f"workspace '{slug}' does not exist")
    return workspace


def dumont_subs_of(user):
    """Every ZITADEL user id linked to this Plane user (a user can have several Dumont accounts)."""
    return sorted(
        {
            sub
            for sub in Account.objects.filter(provider=DUMONT_PROVIDER, user_id=user.id).values_list(
                "provider_account_id", flat=True
            )
            if sub
        }
    )


def build_snapshot(workspace, role_keys, zitadel_grants, only_user_ids=None):
    """Assemble the Snapshot for `workspace`.

    `zitadel_grants` are active grants (zitadel.ZitadelGrant). Every membership of the workspace is
    loaded even for a per-user sync (`only_user_ids`), because the last-admin rule needs the whole
    scope; the plan then only produces changes for those users.
    """
    grants = [
        Grant(
            zitadel_user_id=g.user_id,
            role_keys=tuple(g.role_keys),
            email=g.email,
            display_name=g.display_name,
        )
        for g in zitadel_grants
    ]

    projects = [
        ProjectRef(id=str(pid), identifier=identifier)
        for pid, identifier in Project.objects.filter(workspace_id=workspace.id).values_list("id", "identifier")
    ]
    project_ids = [p.id for p in projects]

    accounts = {
        sub: str(user_id)
        for sub, user_id in Account.objects.filter(
            provider=DUMONT_PROVIDER, provider_account_id__in=[g.zitadel_user_id for g in grants]
        ).values_list("provider_account_id", "user_id")
    }

    ws_rows = WorkspaceMember.objects.filter(workspace_id=workspace.id).values_list("member_id", "role", "is_active")
    workspace_members = {str(uid): Membership(role=role, is_active=active) for uid, role, active in ws_rows}

    project_members = {}
    pm_rows = ProjectMember.objects.filter(project_id__in=project_ids, member__isnull=False).values_list(
        "project_id", "member_id", "role", "is_active"
    )
    for pid, uid, role, active in pm_rows:
        project_members.setdefault(str(pid), {})[str(uid)] = Membership(role=role, is_active=active)

    user_ids = set(workspace_members) | set(accounts.values())
    for members in project_members.values():
        user_ids |= set(members)

    linked = {
        str(uid)
        for uid in Account.objects.filter(provider=DUMONT_PROVIDER, user_id__in=user_ids).values_list(
            "user_id", flat=True
        )
    }
    protected = {
        str(uid)
        for uid in InstanceAdmin.objects.filter(user_id__in=user_ids).values_list("user_id", flat=True)
        if uid is not None
    }
    if workspace.owner_id:
        protected.add(str(workspace.owner_id))

    users = {
        str(uid): PlaneUser(
            id=str(uid),
            email=email or "",
            is_active=is_active,
            is_bot=is_bot,
            protected=str(uid) in protected,
            linked=str(uid) in linked,
        )
        for uid, email, is_active, is_bot in User.objects.filter(id__in=user_ids).values_list(
            "id", "email", "is_active", "is_bot"
        )
    }

    return Snapshot(
        workspace_id=str(workspace.id),
        workspace_slug=workspace.slug,
        role_keys=frozenset(role_keys),
        grants=grants,
        projects=projects,
        accounts=accounts,
        users=users,
        workspace_members=workspace_members,
        project_members=project_members,
        only_user_ids=frozenset(str(u) for u in only_user_ids) if only_user_ids is not None else None,
    )
