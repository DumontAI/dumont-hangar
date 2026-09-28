# Dumont addition: lock membership-changing endpoints of scopes managed in ZITADEL.
# Not upstream Plane. Upstream views only get a one-line decorator.
#
# Only active when DUMONT_ACCESS_SYNC=enforce (off and dry-run never lock). Put the decorator
# BELOW Plane's own permission decorator, so unauthorised callers still get Plane's usual answer:
#
#     @allow_permission([ROLE.ADMIN])
#     @lock_project_membership()
#     def create(self, request, slug, project_id): ...
#
# Which scopes are managed comes from the state the last sync cached (see sync.get_managed_state);
# on a cache miss ZITADEL is asked once. If that fails, membership changes in the configured
# workspace answer 503 instead of guessing (a guess could let a change through that the next sync
# silently reverts, or lock an unmanaged project for no reason).

import functools
import logging
import os

from django.core.exceptions import ValidationError
from rest_framework import status
from rest_framework.response import Response

from plane.dumont.access import roles as R
from plane.dumont.access.config import MODE_ENFORCE, AccessConfigError, load_access_config

logger = logging.getLogger("plane.dumont.access")

ERROR_CODE = "DUMONT_MANAGED_BY_ZITADEL"
UNAVAILABLE_CODE = "DUMONT_ACCESS_STATE_UNAVAILABLE"

# Fields of a membership row that are personal preferences, not access: PATCHes touching only
# these stay allowed on managed scopes.
PROJECT_MEMBER_PREFERENCE_FIELDS = frozenset({"view_props", "default_props", "preferences", "sort_order"})
WORKSPACE_MEMBER_PREFERENCE_FIELDS = frozenset(
    {
        "view_props",
        "default_props",
        "issue_props",
        "company_role",
        "getting_started_checklist",
        "tips",
        "explored_features",
    }
)


class _InvalidConfig:
    """DUMONT_ACCESS_SYNC (or another DUMONT_ACCESS_* value) cannot be parsed. The lock fails closed:
    membership changes in the configured workspace (every workspace when even the slug is unknown)
    answer 503 until the value is fixed, instead of silently reading as `off`."""

    mode = "invalid"

    def __init__(self, error):
        self.error = error
        self.workspace_slug = (os.environ.get("DUMONT_ACCESS_WORKSPACE_SLUG") or "").strip() or None

    def covers(self, slug):
        return self.workspace_slug is None or slug == self.workspace_slug


def _enforce_config():
    try:
        cfg = load_access_config()
    except AccessConfigError as exc:
        logger.error("dumont access: invalid configuration, membership changes fail closed (503): %s", exc)
        return _InvalidConfig(str(exc))
    if cfg.mode != MODE_ENFORCE or not cfg.workspace_slug:
        return None
    return cfg


def _state(cfg):
    if isinstance(cfg, _InvalidConfig):
        raise AccessConfigError(cfg.error)
    from plane.dumont.access.sync import get_managed_state

    return get_managed_state(cfg)


def _unavailable():
    return Response(
        {
            "error_code": UNAVAILABLE_CODE,
            "error": "Membership changes are temporarily unavailable: Hangar could not confirm with Dumont Auth "
            "(ZITADEL) whether this is managed there. Try again in a minute.",
        },
        status=status.HTTP_503_SERVICE_UNAVAILABLE,
    )


def _requested_role_name(request):
    data = getattr(request, "data", None)
    candidates = []
    if hasattr(data, "get"):
        candidates.append(data.get("role"))
        for key in ("members", "emails"):
            items = data.get(key)
            if isinstance(items, list):
                candidates.extend(item.get("role") for item in items if isinstance(item, dict))
    for value in candidates:
        try:
            role = int(value)
        except (TypeError, ValueError):
            continue
        if role in R.NAME_BY_ROLE:
            return R.NAME_BY_ROLE[role]
    return "member"


def project_lock_response(request, project_ids, message=None):
    """403/503 Response when any of `project_ids` is managed and the mode is enforce, else None."""
    cfg = _enforce_config()
    if cfg is None:
        return None
    from plane.db.models import Project

    try:
        queryset = Project.objects.filter(id__in=[pid for pid in project_ids if pid])
        if cfg.workspace_slug is not None:
            queryset = queryset.filter(workspace__slug=cfg.workspace_slug)
        projects = list(queryset.values_list("identifier", flat=True))
    except (ValueError, ValidationError):  # malformed ids: let the view answer as it always did
        return None
    if not projects:
        return None
    try:
        state = _state(cfg)
    except Exception as exc:
        logger.error("dumont access: lock cannot read the managed state (%s)", exc.__class__.__name__)
        return _unavailable()
    managed = set(state.get("identifiers") or [])
    for identifier in projects:
        part = R.identifier_to_key_part(identifier)
        if part and part in managed:
            role = _requested_role_name(request)
            return Response(
                {
                    "error_code": ERROR_CODE,
                    "error": message
                    or (
                        "Access to this project is managed in Dumont Auth (ZITADEL). "
                        f"Ask for role hangar.project.{part}.{role}."
                    ),
                },
                status=status.HTTP_403_FORBIDDEN,
            )
    return None


def workspace_lock_response(request, slugs):
    cfg = _enforce_config()
    if isinstance(cfg, _InvalidConfig):
        return _unavailable() if any(cfg.covers(slug) for slug in slugs) else None
    if cfg is None or cfg.workspace_slug not in set(slugs):
        return None
    try:
        state = _state(cfg)
    except Exception as exc:
        logger.error("dumont access: lock cannot read the managed state (%s)", exc.__class__.__name__)
        return _unavailable()
    if not state.get("workspace_managed"):
        return None
    role = _requested_role_name(request)
    return Response(
        {
            "error_code": ERROR_CODE,
            "error": "Access to this workspace is managed in Dumont Auth (ZITADEL). "
            f"Ask for role hangar.workspace.{role}.",
        },
        status=status.HTTP_403_FORBIDDEN,
    )


def touches_fields_outside(allowed):
    """Predicate: the request body changes something other than `allowed` (preference) fields."""

    def predicate(request, kwargs):
        data = getattr(request, "data", None)
        if not hasattr(data, "keys"):
            return True
        return any(key not in allowed for key in data.keys())

    return predicate


def changes_project_identifier(request, kwargs):
    """Predicate for project PATCH: renaming the identifier would move the project out of management."""
    data = getattr(request, "data", None)
    new = data.get("identifier") if hasattr(data, "get") else None
    if not new:
        return False
    from plane.db.models import Project

    current = Project.objects.filter(id=kwargs.get("pk")).values_list("identifier", flat=True).first()
    return current is not None and str(new).strip().upper() != current.strip().upper()


IDENTIFIER_LOCK_MESSAGE = (
    "Access to this project is managed in Dumont Auth (ZITADEL) through its identifier; renaming the "
    "identifier would take it out of that management. Ask for the ZITADEL roles to be moved first."
)


def lock_project_identifier_change():
    """Decorator for project PATCH endpoints (project id in kwarg `pk`)."""
    return lock_project_membership(
        project_kwarg="pk", only_if=changes_project_identifier, message=IDENTIFIER_LOCK_MESSAGE
    )


def lock_project_membership(project_kwarg="project_id", project_ids_from=None, only_if=None, message=None):
    """Decorator for a view method (self, request, *args, **kwargs) that changes project memberships."""

    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped(instance, request, *args, **kwargs):
            # Cheap mode check first: outside enforce the lock costs no query at all.
            if _enforce_config() is not None and (only_if is None or only_if(request, kwargs)):
                ids = project_ids_from(request, kwargs) if project_ids_from else [kwargs.get(project_kwarg)]
                denied = project_lock_response(request, ids, message=message)
                if denied is not None:
                    return denied
            return view_func(instance, request, *args, **kwargs)

        return wrapped

    return decorator


def lock_workspace_membership(slugs_from=None, only_if=None):
    """Decorator for a view method that changes workspace memberships (slug from kwargs by default)."""

    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped(instance, request, *args, **kwargs):
            if _enforce_config() is not None and (only_if is None or only_if(request, kwargs)):
                slugs = slugs_from(request, kwargs) if slugs_from else [kwargs.get("slug")]
                denied = workspace_lock_response(request, slugs)
                if denied is not None:
                    return denied
            return view_func(instance, request, *args, **kwargs)

        return wrapped

    return decorator


PROJECT_LEAD_LOCK_MESSAGE = (
    "Access to project {identifier} is managed in Dumont Auth (ZITADEL). A project lead other than you "
    "would become its admin here; create the project without a different lead and ask for role "
    "hangar.project.{part}.admin for that person."
)


def _body_value(request, key):
    data = getattr(request, "data", None)
    return data.get(key) if hasattr(data, "get") else None


def _queue_full_sync():
    """Queue one full sync after the current transaction commits. Never raises into the view."""

    def enqueue():
        try:
            from plane.dumont.access.tasks import dumont_access_full_sync

            dumont_access_full_sync.delay()
        except Exception:
            logger.warning("dumont access: could not queue a full sync after project create; the beat will run it")

    try:
        from django.db import transaction

        transaction.on_commit(enqueue)
    except Exception:
        logger.warning("dumont access: could not schedule a full sync after project create")


def lock_project_create():
    """Decorator for project create endpoints (workspace slug in kwarg `slug`).

    Plane makes the creator admin of a new project, and a `project_lead` other than the creator too.
    When the new identifier already has roles in ZITADEL, the project is managed from birth, so in
    enforce mode:
      - naming a different project lead is refused (it would grant admin to someone ZITADEL did not);
      - after a successful create a full sync is queued, so the creator's provisional admin row is
        reconciled with the grants right away (the last-admin rule keeps it while ZITADEL has no admin).
    Creating the project itself stays allowed: roles may be prepared in ZITADEL before the project exists.
    """

    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped(instance, request, *args, **kwargs):
            cfg = _enforce_config()
            if isinstance(cfg, _InvalidConfig):
                if not cfg.covers(kwargs.get("slug")):
                    return view_func(instance, request, *args, **kwargs)
            elif cfg is None or kwargs.get("slug") != cfg.workspace_slug:
                return view_func(instance, request, *args, **kwargs)
            identifier = _body_value(request, "identifier")
            part = R.identifier_to_key_part(str(identifier)) if identifier else None
            lead = _body_value(request, "project_lead")
            user_id = str(getattr(request.user, "id", ""))
            if part and lead and str(lead) != user_id:
                try:
                    state = _state(cfg)
                except Exception as exc:
                    logger.error("dumont access: lock cannot read the managed state (%s)", exc.__class__.__name__)
                    return _unavailable()
                if part in set(state.get("identifiers") or []):
                    return Response(
                        {
                            "error_code": ERROR_CODE,
                            "error": PROJECT_LEAD_LOCK_MESSAGE.format(identifier=str(identifier).upper(), part=part),
                        },
                        status=status.HTTP_403_FORBIDDEN,
                    )
            response = view_func(instance, request, *args, **kwargs)
            if getattr(response, "status_code", None) == status.HTTP_201_CREATED:
                _queue_full_sync()
            return response

        return wrapped

    return decorator


# --- extractors for endpoints whose targets are in the body ------------------------------------


def project_ids_in_body(request, kwargs):
    data = getattr(request, "data", None)
    ids = data.get("project_ids") if hasattr(data, "get") else None
    return [str(pid) for pid in ids] if isinstance(ids, list) else []


def workspace_slugs_of_invitations(request, kwargs):
    from plane.db.models import WorkspaceMemberInvite

    data = getattr(request, "data", None)
    ids = data.get("invitations") if hasattr(data, "get") else None
    if not isinstance(ids, list) or not ids:
        return []
    try:
        return list(
            WorkspaceMemberInvite.objects.filter(pk__in=ids).values_list("workspace__slug", flat=True).distinct()
        )
    except Exception:  # malformed ids: let the view answer as it always did
        return []
