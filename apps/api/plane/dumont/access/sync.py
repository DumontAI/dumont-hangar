# Dumont addition: the ZITADEL -> Hangar membership reconciler (full and per-user).
# Not upstream Plane.
#
# Fail safe everywhere: if the configuration is incomplete, ZITADEL is unreachable or answers an
# error, nothing is written and the previous state stays. The full sync in enforce mode also has a
# safety brake: when more than DUMONT_ACCESS_MAX_REMOVALS distinct users would lose or reduce access
# it writes nothing and logs loudly, because that pattern is far more likely a ZITADEL-side mistake
# (wrong project id, a lost permission, an empty answer) than a real mass revocation.
#
# The per-user sync (login and bearer hooks) only ADDS access: create, reactivate, role upgrade.
# Removals and demotions are reported as `deferred_to_full_sync` and left to the full sync, so no
# single request can take access away without passing the brake. After any ZITADEL error the hooks
# back off for ZITADEL_BACKOFF_TTL seconds, so an outage does not add a slow call to every request.

import dataclasses
import hashlib
import logging
import time

from django.core.cache import cache

from plane.dumont.access import roles as R
from plane.dumont.access.apply import apply_plan
from plane.dumont.access.config import MODE_DRY_RUN, MODE_ENFORCE, MODE_OFF, AccessConfigError, load_access_config
from plane.dumont.access.plan import compute_plan, managed_scopes
from plane.dumont.access.snapshot import WorkspaceNotFound, build_snapshot, dumont_subs_of, load_workspace
from plane.dumont.access.zitadel import ZitadelClient, ZitadelError

logger = logging.getLogger("plane.dumont.access")

CACHE_PREFIX = "dumont_access:"
MANAGED_STATE_KEY = CACHE_PREFIX + "managed_state"
MANAGED_STATE_TTL = 60 * 60
FULL_SYNC_LOCK_KEY = CACHE_PREFIX + "full_sync_lock"
FULL_SYNC_LOCK_TTL = 4 * 60
USER_SYNC_TTL = 60
ZITADEL_BACKOFF_KEY = CACHE_PREFIX + "zitadel_backoff"
ZITADEL_BACKOFF_TTL = 60

STATUS_OFF = "off"
STATUS_DRY_RUN = "dry_run"
STATUS_APPLIED = "applied"
STATUS_BRAKE = "aborted_brake"
STATUS_ERROR = "error"
STATUS_BUSY = "busy"
STATUS_SKIPPED = "skipped"


def make_client(cfg):
    return ZitadelClient(cfg.base_url, cfg.org_id, cfg.load_service_key())


def user_sync_cache_key(sub):
    return CACHE_PREFIX + "user_sync:" + hashlib.sha256(sub.encode("utf-8")).hexdigest()[:32]


def start_zitadel_backoff():
    """After a ZitadelError: the per-user hooks skip ZITADEL for ZITADEL_BACKOFF_TTL seconds."""
    try:
        cache.set(ZITADEL_BACKOFF_KEY, 1, ZITADEL_BACKOFF_TTL)
    except Exception:
        logger.warning("dumont access: could not store the ZITADEL backoff flag in the cache")


def zitadel_backoff_active():
    """True while the backoff flag is set. Raises when the cache is unreachable (callers skip then)."""
    return bool(cache.get(ZITADEL_BACKOFF_KEY))


# --- managed state (used by the endpoint lock) ------------------------------------------------


def _store_managed_state(cfg, role_keys, workspace):
    from plane.db.models import Project

    identifiers = [
        R.identifier_to_key_part(identifier)
        for identifier in Project.objects.filter(workspace_id=workspace.id).values_list("identifier", flat=True)
    ]
    workspace_managed, managed_parts, _, _ = managed_scopes(set(role_keys), set(identifiers))
    state = {
        "workspace_slug": workspace.slug,
        "workspace_managed": workspace_managed,
        # Identifiers WITH roles, even without a Plane project yet, so that a project created or renamed
        # into a managed identifier is locked at once.
        "identifiers": sorted(
            {parsed.identifier for parsed in map(R.parse_role_key, role_keys) if parsed and parsed.identifier}
        ),
        "managed_identifiers": managed_parts,
        "at": int(time.time()),
    }
    try:
        cache.set(MANAGED_STATE_KEY, state, MANAGED_STATE_TTL)
    except Exception:  # cache outage must not break the sync
        logger.warning("dumont access: could not store the managed state in the cache")
    return state


def get_managed_state(cfg):
    """The managed scopes, from the cache or (on a miss) from ZITADEL. Raises on failure."""
    try:
        state = cache.get(MANAGED_STATE_KEY)
    except Exception:
        state = None
    if state and state.get("workspace_slug") == cfg.workspace_slug:
        return state
    cfg.require_complete()
    workspace = load_workspace(cfg.workspace_slug)
    role_keys = make_client(cfg).list_project_role_keys(cfg.project_id)
    return _store_managed_state(cfg, role_keys, workspace)


# --- reports ----------------------------------------------------------------------------------


def _report(status, mode, scope, plan=None, snapshot=None, result=None, error=None, **extra):
    report = {"status": status, "mode": mode, "scope": scope}
    if error:
        report["error"] = error
    if plan is not None:
        users = snapshot.users if snapshot else {}
        report.update(
            {
                "managed": {
                    "workspace": plan.managed_workspace,
                    "projects": sorted(plan.managed_projects.values()),
                },
                "changes": [change.as_dict(users) for change in plan.changes],
                # Cascaded rows (unmanaged projects included) are also in `changes`; listed apart
                # because they are not reverted automatically if the removal was a mistake.
                "cascaded": [change.as_dict(users) for change in plan.cascaded],
                "deferred_to_full_sync": [change.as_dict(users) for change in plan.deferred],
                "pending": plan.pending,
                "notes": plan.notes,
                "unknown_project_roles": plan.unknown_project_roles,
                "invalid_role_keys": plan.invalid_role_keys,
                "identifier_collisions": plan.identifier_collisions,
                "ignored_grants": plan.ignored_grants,
                "counts": {
                    "changes": len(plan.changes),
                    "deactivations": len(plan.deactivations),
                    "users_losing_access": len(plan.users_losing_access),
                    "cascaded": len(plan.cascaded),
                    "deferred_to_full_sync": len(plan.deferred),
                    "pending": len(plan.pending),
                    "ignored_grants": len(plan.ignored_grants),
                },
            }
        )
    if result is not None:
        report["applied"] = len(result["applied"])
        report["stale"] = [{**change.as_dict(), "reason": reason} for change, reason in result["stale"]]
        report["failed_scopes"] = result["failed_scopes"]
    report.update(extra)
    return report


def _ignored_grants(client=None, ignored=None):
    """Grants dropped at the ZITADEL organisation boundary; logged as a warning (ids only)."""
    ignored = list(ignored if ignored is not None else (getattr(client, "ignored_grants", None) or []))
    if ignored:
        logger.warning(
            "dumont access: ignored %d grant(s) outside the Dumont organisation (DUMONT_ZITADEL_ORG_ID): %s",
            len(ignored),
            ignored[:50],
        )
    return ignored


def _log_plan(report):
    """One structured line per sync; user ids, never e-mails or tokens."""
    changes = [
        f"{c['action']}:{c['scope']}:{c['user_id']}:{c['from_role']}->{c['to_role']}" for c in report.get("changes", [])
    ]
    logger.info(
        "dumont access %s sync status=%s mode=%s changes=%d pending=%d detail=%s",
        report["scope"],
        report["status"],
        report["mode"],
        len(changes),
        len(report.get("pending", [])),
        changes[:200],
    )


def _log_cascade(changes, outcome):
    """One WARNING per cascaded row (project identifier + user id), so a mistaken removal can be undone
    by hand from the log: the cascade into unmanaged projects is not reverted automatically."""
    for change in changes:
        if change.cascade:
            logger.warning(
                "dumont access: cascade %s: %s project=%s project_id=%s user_id=%s role %s->%s",
                outcome,
                change.action,
                change.label,
                change.scope_id,
                change.user_id,
                R.role_name(change.from_role) if change.from_role is not None else "-",
                R.role_name(change.to_role) if change.to_role is not None else "-",
            )


def _invalidate_plane_caches(slug):
    try:
        from plane.utils.cache import invalidate_cache_directly

        for path in (f"/api/workspaces/{slug}/members/", "/api/users/me/workspaces/", "/api/users/me/settings/"):
            invalidate_cache_directly(path=path, user=False, multiple=True)
    except Exception:
        logger.warning("dumont access: could not invalidate Plane response caches")


# --- entry points -----------------------------------------------------------------------------


def _resolve_mode(cfg, mode):
    if mode is None:
        return cfg.mode
    if mode not in (MODE_OFF, MODE_DRY_RUN, MODE_ENFORCE):
        raise AccessConfigError(f"unknown mode {mode!r}")
    if mode == MODE_ENFORCE and cfg.mode != MODE_ENFORCE:
        # enforce without the environment in enforce would write memberships while the endpoint
        # lock stays off; refuse so the two can never disagree.
        raise AccessConfigError("--mode enforce requires DUMONT_ACCESS_SYNC=enforce")
    return mode


def run_full_sync(mode=None, max_removals=None):
    """Full reconciliation of the configured workspace. Never raises; returns a report dict.

    `max_removals` overrides DUMONT_ACCESS_MAX_REMOVALS for this run only (the manual command's
    --max-removals, after a dry-run confirmed the removals are real).
    """
    try:
        cfg = load_access_config()
        mode = _resolve_mode(cfg, mode)
        if max_removals is not None:
            if isinstance(max_removals, bool) or not isinstance(max_removals, int) or max_removals < 0:
                raise AccessConfigError("max_removals must be an integer >= 0")
            cfg = dataclasses.replace(cfg, max_removals=max_removals)
    except AccessConfigError as exc:
        logger.error("dumont access: configuration error: %s", exc)
        return _report(STATUS_ERROR, mode or "?", "full", error=str(exc))
    if mode == MODE_OFF:
        return _report(STATUS_OFF, mode, "full")

    try:
        acquired = cache.add(FULL_SYNC_LOCK_KEY, 1, FULL_SYNC_LOCK_TTL)
    except Exception:
        acquired = True  # no cache: run anyway; row-level checks in apply keep it consistent
    if not acquired:
        return _report(STATUS_BUSY, mode, "full")
    try:
        return _full_sync(cfg, mode)
    except Exception as exc:  # last line of defence: a sync bug must never escape into beat/commands
        logger.exception("dumont access: full sync failed")
        return _report(STATUS_ERROR, mode, "full", error=f"internal error ({exc.__class__.__name__})")
    finally:
        try:
            cache.delete(FULL_SYNC_LOCK_KEY)
        except Exception:
            pass


def _full_sync(cfg, mode):
    try:
        cfg.require_complete()
        workspace = load_workspace(cfg.workspace_slug)
        client = make_client(cfg)
        role_keys = client.list_project_role_keys(cfg.project_id)
        grants = client.list_user_grants(cfg.project_id)
    except (AccessConfigError, WorkspaceNotFound, ZitadelError) as exc:
        if isinstance(exc, ZitadelError):
            start_zitadel_backoff()
        logger.error("dumont access: full sync changed nothing: %s", exc)
        return _report(STATUS_ERROR, mode, "full", error=str(exc))

    _store_managed_state(cfg, role_keys, workspace)
    snapshot = build_snapshot(workspace, role_keys, grants)
    plan = compute_plan(snapshot)
    plan.ignored_grants = _ignored_grants(client)

    if mode == MODE_DRY_RUN:
        _log_cascade(plan.changes, "planned (dry-run, not written)")
        report = _report(STATUS_DRY_RUN, mode, "full", plan, snapshot)
        _log_plan(report)
        return report

    # The brake counts PEOPLE losing or reducing access (deactivation or downgrade, cascades
    # included), not rows: one removed user with ten project rows is one decision.
    losing = plan.users_losing_access
    if len(losing) > cfg.max_removals:
        logger.critical(
            "dumont access: SAFETY BRAKE - full sync would remove or reduce the access of %d users (limit %d, "
            "DUMONT_ACCESS_MAX_REMOVALS); nothing was written. Check the ZITADEL project/grants, then run "
            "`manage.py dumont_access_sync --mode dry-run` to review; if the removals are real, run once with "
            "`--max-removals N`.",
            len(losing),
            cfg.max_removals,
        )
        _log_cascade(plan.changes, "planned (brake, not written)")
        report = _report(STATUS_BRAKE, mode, "full", plan, snapshot, max_removals=cfg.max_removals)
        _log_plan(report)
        return report

    result = apply_plan(plan, workspace)
    if result["applied"]:
        _invalidate_plane_caches(workspace.slug)
    _log_cascade(result["applied"], "applied")
    report = _report(STATUS_APPLIED, mode, "full", plan, snapshot, result)
    _log_plan(report)
    return report


def run_user_sync(user, sub, mode=None):
    """Sync one user's memberships from their ZITADEL grants. Never raises; returns a report dict."""
    try:
        cfg = load_access_config()
        mode = _resolve_mode(cfg, mode)
    except AccessConfigError as exc:
        logger.error("dumont access: configuration error: %s", exc)
        return _report(STATUS_ERROR, mode or "?", "user", error=str(exc))
    if mode == MODE_OFF:
        return _report(STATUS_OFF, mode, "user")
    try:
        return _user_sync(cfg, mode, user, sub)
    except Exception as exc:
        logger.exception("dumont access: per-user sync failed")
        return _report(STATUS_ERROR, mode, "user", error=f"internal error ({exc.__class__.__name__})")


def _user_sync(cfg, mode, user, sub):
    if user is None or not sub or getattr(user, "is_bot", False):
        return _report(STATUS_OFF, mode, "user", error="no user/sub or bot user")
    try:
        cfg.require_complete()
        workspace = load_workspace(cfg.workspace_slug)
        # A Plane user can have several Dumont accounts (one per ZITADEL user that signed in with the
        # same verified e-mail). Grants of all of them count, like in the full sync; looking only at
        # the login sub would read "no grants" and plan the removal of everything the others grant.
        subs = dumont_subs_of(user)
        if sub not in subs:
            logger.error("dumont access: the login sub is not linked to this Plane user; per-user sync skipped")
            return _report(STATUS_ERROR, mode, "user", error="sub not linked to this user")
        client = make_client(cfg)
        role_keys = client.list_project_role_keys(cfg.project_id)
        in_org = client.user_ids_in_org(subs)
        if sub not in in_org:
            # Signed in with a ZITADEL user of another organisation: that login proves nothing about
            # Dumont access, so it changes nothing (the web login refuses such users when
            # DUMONT_ZITADEL_ORG_ID is set; this also covers the bearer path and older sessions).
            logger.warning("dumont access: login sub is not a user of the Dumont organisation; per-user sync skipped")
            return _report(STATUS_SKIPPED, mode, "user", error="login sub outside the Dumont organisation")
        grants = []
        ignored = [{"user_id": other, "reason": "user_outside_org"} for other in subs if other not in in_org]
        for linked_sub in sorted(in_org):
            # Only grants of this ZITADEL user (the client filters too).
            grants.extend(
                g for g in client.list_user_grants(cfg.project_id, user_id=linked_sub) if g.user_id == linked_sub
            )
            ignored.extend(item for item in client.ignored_grants if item["user_id"] == linked_sub)
    except (AccessConfigError, WorkspaceNotFound, ZitadelError) as exc:
        if isinstance(exc, ZitadelError):
            start_zitadel_backoff()
        logger.error("dumont access: per-user sync changed nothing: %s", exc)
        return _report(STATUS_ERROR, mode, "user", error=str(exc))

    _store_managed_state(cfg, role_keys, workspace)
    snapshot = build_snapshot(workspace, role_keys, grants, only_user_ids={user.id})
    if any(snapshot.accounts.get(g.user_id) not in (None, str(user.id)) for g in grants):
        logger.error("dumont access: a sub is linked to another Plane user; per-user sync skipped")
        return _report(STATUS_ERROR, mode, "user", error="sub linked to another user")
    # Additive only: removals and demotions wait for the full sync (and its brake).
    plan = compute_plan(snapshot, additive_only=True)
    plan.ignored_grants = _ignored_grants(ignored=ignored)
    if mode == MODE_DRY_RUN:
        report = _report(STATUS_DRY_RUN, mode, "user", plan, snapshot)
        _log_plan(report)
        return report
    result = apply_plan(plan, workspace)
    if result["applied"]:
        _invalidate_plane_caches(workspace.slug)
    report = _report(STATUS_APPLIED, mode, "user", plan, snapshot, result)
    _log_plan(report)
    return report
