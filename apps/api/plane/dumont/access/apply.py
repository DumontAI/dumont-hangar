# Dumont addition: write a membership plan to the database.
# Not upstream Plane.
#
# One transaction per scope (the workspace, then each project). Every row is re-read with
# SELECT ... FOR UPDATE and must still be in the state the plan saw; otherwise that change is
# skipped as "stale" (someone changed it meanwhile; the next sync re-plans). Rows are never
# hard-deleted: removal is is_active=False, exactly like Plane's own "remove member".

import logging
from collections import OrderedDict

from django.db import DatabaseError, transaction
from django.db.models import Min

from plane.db.models import Project, ProjectMember, ProjectUserProperty, WorkspaceMember
from plane.dumont.access.plan import CREATE, DEACTIVATE, PROJECT, REACTIVATE, UPDATE_ROLE, WORKSPACE

logger = logging.getLogger("plane.dumont.access")


class _Stale(Exception):
    pass


def apply_plan(plan, workspace):
    """Apply `plan.changes`. Returns {"applied": [...], "stale": [...], "failed_scopes": [...]}."""
    result = {"applied": [], "stale": [], "failed_scopes": []}
    groups = OrderedDict()
    for change in plan.changes:
        groups.setdefault((change.scope, change.scope_id), []).append(change)
    ordered = sorted(groups.items(), key=lambda item: 0 if item[0][0] == WORKSPACE else 1)

    workspace_failed = False
    for (scope, scope_id), changes in ordered:
        label = changes[0].label or scope
        if scope == PROJECT and workspace_failed:
            result["failed_scopes"].append({"scope": label, "error": "skipped: workspace scope failed"})
            continue
        applied, stale = [], []
        try:
            with transaction.atomic():
                for change in changes:
                    try:
                        with transaction.atomic():  # savepoint: a stale row must not abort the scope
                            if scope == WORKSPACE:
                                _apply_workspace_change(change, workspace)
                            else:
                                _apply_project_change(change)
                        applied.append(change)
                    except _Stale as exc:
                        stale.append((change, str(exc)))
        except DatabaseError as exc:
            logger.error(
                "dumont access: scope %s rolled back (%s); nothing written for it", label, exc.__class__.__name__
            )
            result["failed_scopes"].append({"scope": label, "error": exc.__class__.__name__})
            if scope == WORKSPACE:
                workspace_failed = True
            continue
        result["applied"].extend(applied)
        result["stale"].extend(stale)
    return result


def _check(row, change):
    if change.action == CREATE:
        if row is not None:
            raise _Stale("row appeared since the plan was made")
        return
    if row is None:
        raise _Stale("row disappeared since the plan was made")
    if row.is_active != change.from_active or row.role != change.from_role:
        raise _Stale("row changed since the plan was made")


def _apply_workspace_change(change, workspace):
    row = (
        WorkspaceMember.objects.select_for_update().filter(workspace_id=workspace.id, member_id=change.user_id).first()
    )
    _check(row, change)
    if change.action == CREATE:
        WorkspaceMember(workspace_id=workspace.id, member_id=change.user_id, role=change.to_role).save(
            disable_auto_set_user=True
        )
    elif change.action == REACTIVATE:
        row.is_active = True
        row.role = change.to_role
        row.save(update_fields=["is_active", "role", "updated_at"], disable_auto_set_user=True)
    elif change.action == UPDATE_ROLE:
        row.role = change.to_role
        row.save(update_fields=["role", "updated_at"], disable_auto_set_user=True)
    elif change.action == DEACTIVATE:
        row.is_active = False
        row.save(update_fields=["is_active", "updated_at"], disable_auto_set_user=True)


def _apply_project_change(change):
    row = ProjectMember.objects.select_for_update().filter(project_id=change.scope_id, member_id=change.user_id).first()
    _check(row, change)
    if change.action == CREATE:
        _create_project_member(change.scope_id, change.user_id, change.to_role)
    elif change.action == REACTIVATE:
        row.is_active = True
        row.role = change.to_role
        row.save(update_fields=["is_active", "role", "updated_at"], disable_auto_set_user=True)
    elif change.action == UPDATE_ROLE:
        row.role = change.to_role
        row.save(update_fields=["role", "updated_at"], disable_auto_set_user=True)
    elif change.action == DEACTIVATE:
        row.is_active = False
        row.save(update_fields=["is_active", "updated_at"], disable_auto_set_user=True)


def _create_project_member(project_id, user_id, role):
    """Create the ProjectMember plus its ProjectUserProperty, as ProjectMemberViewSet.create does.

    ProjectMember.save() always creates a ProjectUserProperty, which collides with one left behind
    by an earlier membership; bulk_create skips save() so we handle the property ourselves.
    """
    project = Project.objects.get(pk=project_id)
    ProjectMember.objects.bulk_create(
        [ProjectMember(project_id=project.id, workspace_id=project.workspace_id, member_id=user_id, role=role)]
    )
    if not ProjectUserProperty.objects.filter(project_id=project.id, user_id=user_id).exists():
        min_sort_order = ProjectUserProperty.objects.filter(
            workspace_id=project.workspace_id, user_id=user_id
        ).aggregate(value=Min("sort_order"))["value"]
        ProjectUserProperty(
            workspace_id=project.workspace_id,
            project_id=project.id,
            user_id=user_id,
            sort_order=(min_sort_order - 10000 if min_sort_order is not None else 65535),
        ).save(disable_auto_set_user=True)
