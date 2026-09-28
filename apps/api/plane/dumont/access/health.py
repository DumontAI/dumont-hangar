# Dumont addition: health of the ZITADEL -> Hangar full sync, for an external monitor.
# Not upstream Plane.
#
# Every full sync in the configured mode records its outcome in the Django cache (Redis): status,
# a reason code, aggregate counts, when it ran and how many runs in a row did not apply. No database
# table, no migration. `GET /api/dumont/access-sync/status/` reads that one cache key and answers:
#
#   200  mode off or dry-run (nothing to watch), or enforce and healthy
#   503  mode enforce and: no run recorded, the last run is older than STALE_AFTER_SECONDS, or the
#        last FAILURES_TO_ALERT runs in a row ended in error or safety brake; also an unparseable
#        configuration (a typo in DUMONT_ACCESS_SYNC) and an unreachable cache
#
# The body is minimal on purpose (the endpoint is public): mode, last status, reason code, last run
# time, age, consecutive failures. No user names, e-mails, ids or per-person counts. It is a plain
# Django view: no DRF authentication and no DRF throttle, so a monitor polling it every minute can
# never be throttled into a false alert, and it costs one cache read.

import os
import time

from django.core.cache import cache
from django.http import JsonResponse
from django.views import View

from plane.dumont.access.config import MODE_DRY_RUN, MODE_ENFORCE, MODE_OFF, AccessConfigError, load_access_config

LAST_FULL_SYNC_KEY = "dumont_access:last_full_sync"
RECORD_TTL = 7 * 24 * 60 * 60
STALE_AFTER_SECONDS = 20 * 60  # the beat runs every 5 minutes: 4 missed runs
FAILURES_TO_ALERT = 2
FAILING_STATUSES = ("error", "aborted_brake")
RECORDED_STATUSES = ("applied", "dry_run", "error", "aborted_brake")


def record_full_sync(report, now=None):
    """Store the outcome of one full sync. Never raises (a cache outage must not break the sync)."""
    status = report.get("status")
    if status not in RECORDED_STATUSES:
        return None  # off / busy say nothing about the health of the sync
    now = time.time() if now is None else now
    try:
        previous = cache.get(LAST_FULL_SYNC_KEY) or {}
    except Exception:
        previous = {}
    failures = int(previous.get("consecutive_failures") or 0) + 1 if status in FAILING_STATUSES else 0
    counts = report.get("counts") or {}
    record = {
        "status": status,
        "reason": report.get("reason") or ("ok" if status not in FAILING_STATUSES else "unknown"),
        "mode": report.get("mode"),
        "at": int(now),
        "consecutive_failures": failures,
        # aggregate numbers only, for the operator reading the cache; never served by the endpoint
        "counts": {key: counts.get(key) for key in ("changes", "users_losing_access", "pending") if key in counts},
    }
    try:
        cache.set(LAST_FULL_SYNC_KEY, record, RECORD_TTL)
    except Exception:
        return None
    return record


def sync_health(now=None):
    """(http status, body) for the status endpoint."""
    now = time.time() if now is None else now
    try:
        mode = load_access_config().mode
    except AccessConfigError:
        raw_mode = (os.environ.get("DUMONT_ACCESS_SYNC") or MODE_OFF).strip().lower()
        if raw_mode in (MODE_OFF, MODE_DRY_RUN):
            # Same rule as the lock: the mode says nothing is enforced, so nothing is stuck.
            return 200, {"mode": raw_mode, "healthy": True, "config_error": True}
        return 503, {
            "mode": raw_mode if raw_mode == MODE_ENFORCE else "invalid",
            "healthy": False,
            "reason": "config_error",
        }
    body = {"mode": mode}
    try:
        record = cache.get(LAST_FULL_SYNC_KEY)
    except Exception:
        record = None
        if mode == MODE_ENFORCE:
            return 503, {**body, "healthy": False, "reason": "state_unavailable"}
    if record:
        age = max(0, int(now - int(record.get("at") or 0)))
        body.update(
            {
                "last_status": record.get("status"),
                "last_reason": record.get("reason"),
                "last_run_at": int(record.get("at") or 0),
                "age_seconds": age,
                "consecutive_failures": int(record.get("consecutive_failures") or 0),
            }
        )
    if mode != MODE_ENFORCE:
        return 200, {**body, "healthy": True}
    if not record:
        return 503, {**body, "healthy": False, "reason": "no_run_recorded"}
    if body["age_seconds"] > STALE_AFTER_SECONDS:
        return 503, {**body, "healthy": False, "reason": "stale"}
    if body["consecutive_failures"] >= FAILURES_TO_ALERT:
        return 503, {**body, "healthy": False, "reason": record.get("reason") or "failing"}
    return 200, {**body, "healthy": True}


class AccessSyncStatusEndpoint(View):
    """GET /api/dumont/access-sync/status/ (public, minimal, one cache read)."""

    http_method_names = ["get", "head"]

    def get(self, request):
        status, body = sync_health()
        response = JsonResponse(body, status=status)
        response["Cache-Control"] = "no-store"
        return response
