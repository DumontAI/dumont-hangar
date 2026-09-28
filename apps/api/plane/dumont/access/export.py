# Dumont addition: export current Hangar memberships as proposed ZITADEL roles and user grants.
# Not upstream Plane. Read-only; feeds scripts/dumont/zitadel_access_bootstrap.py.

import csv
import io
from datetime import datetime, timezone

from plane.db.models import Account, Project, ProjectMember, WorkspaceMember
from plane.dumont.access import roles as R
from plane.dumont.access.snapshot import DUMONT_PROVIDER, load_workspace

EXPORT_FORMAT = "hangar-zitadel-access-export/v1"
ROLE_GROUP = "hangar"
NO_LOGIN_NOTE = "no Dumont login yet"


def _role_entry(scope, identifier, role, project_name=None):
    key = R.role_key(scope, identifier, role)
    name = R.role_name(role)
    if scope == R.WORKSPACE_SCOPE:
        display = f"Hangar workspace {name}"
    else:
        display = f"Hangar {identifier.upper()} {name}" + (f" ({project_name})" if project_name else "")
    return {"key": key, "display_name": display[:200], "group": ROLE_GROUP}


def build_export(workspace_slug):
    workspace = load_workspace(workspace_slug)
    users = {}
    skipped = []

    def entry(member):
        uid = str(member.id)
        if uid not in users:
            users[uid] = {
                "plane_user_id": uid,
                "email": member.email,
                "display_name": member.display_name or "",
                "zitadel_user_id": None,
                "linked": False,
                "note": NO_LOGIN_NOTE,
                "roles": set(),
            }
        return users[uid]

    ws_rows = WorkspaceMember.objects.filter(workspace_id=workspace.id, is_active=True).select_related("member")
    active_ws_members = set()
    for row in ws_rows:
        if row.member.is_bot:
            skipped.append({"kind": "user", "email": row.member.email, "reason": "bot"})
            continue
        if not row.member.is_active:
            skipped.append({"kind": "user", "email": row.member.email, "reason": "plane user deactivated"})
            continue
        active_ws_members.add(str(row.member_id))
        entry(row.member)["roles"].add(R.role_key(R.WORKSPACE_SCOPE, None, row.role))

    roles = [_role_entry(R.WORKSPACE_SCOPE, None, role) for role in (R.ADMIN, R.MEMBER, R.GUEST)]
    projects = Project.objects.filter(workspace_id=workspace.id).order_by("identifier")
    for project in projects:
        part = R.identifier_to_key_part(project.identifier)
        members = ProjectMember.objects.filter(
            project_id=project.id, is_active=True, member__isnull=False
        ).select_related("member")
        exported = 0
        for row in members:
            if row.member.is_bot or str(row.member_id) not in active_ws_members:
                continue
            if part is None:
                continue
            entry(row.member)["roles"].add(R.role_key(R.PROJECT_SCOPE, part, row.role))
            exported += 1
        if part is None:
            skipped.append(
                {
                    "kind": "project",
                    "identifier": project.identifier,
                    "reason": "identifier cannot be expressed as a role key (allowed: a-z, 0-9, _)",
                }
            )
        elif exported:
            roles.extend(
                _role_entry(R.PROJECT_SCOPE, part, role, project.name) for role in (R.ADMIN, R.MEMBER, R.GUEST)
            )

    accounts = Account.objects.filter(provider=DUMONT_PROVIDER, user_id__in=list(users)).values_list(
        "user_id", "provider_account_id"
    )
    by_user = {}
    for uid, sub in accounts:
        by_user.setdefault(str(uid), []).append(sub)
    for uid, subs in by_user.items():
        if len(subs) == 1:
            users[uid].update({"zitadel_user_id": subs[0], "linked": True, "note": None})
        else:
            users[uid]["note"] = "several Dumont accounts linked; resolve by hand"

    user_list = []
    for data in sorted(users.values(), key=lambda item: item["email"]):
        data["roles"] = sorted(data["roles"])
        user_list.append(data)
    return {
        "format": EXPORT_FORMAT,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workspace": workspace.slug,
        "roles": roles,
        "users": user_list,
        "skipped": skipped,
    }


def export_to_csv(export):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["email", "zitadel_user_id", "linked", "role_key", "note"])
    for user in export["users"]:
        for key in user["roles"]:
            writer.writerow(
                [
                    _csv_safe(user["email"]),
                    user["zitadel_user_id"] or "",
                    "yes" if user["linked"] else "no",
                    key,
                    _csv_safe(user["note"] or ""),
                ]
            )
    return buffer.getvalue()


def _csv_safe(value):
    """Neutralise spreadsheet formulas (same concern as plane's CSV export sanitisation)."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text
