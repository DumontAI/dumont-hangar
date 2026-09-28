# Dumont addition: Celery beat entry point of the ZITADEL -> Hangar membership sync.
# Not upstream Plane. Scheduled every 5 minutes in plane/celery.py; a no-op in mode `off`.

import logging

from celery import shared_task

from plane.dumont.access.config import MODE_OFF, AccessConfigError, load_access_config

logger = logging.getLogger("plane.dumont.access")


@shared_task(name="plane.dumont.access.tasks.dumont_access_full_sync", ignore_result=True)
def dumont_access_full_sync():
    try:
        cfg = load_access_config()
    except AccessConfigError as exc:
        # A typo in DUMONT_ACCESS_SYNC (or DUMONT_ACCESS_MAX_REMOVALS) must be loud every 5 minutes,
        # not read as `off`: the operator meant the sync to run.
        logger.error("dumont access: configuration error, full sync not run: %s", exc)
        return {"status": "error", "error": str(exc)}
    if cfg.mode == MODE_OFF:
        return {"status": "off"}
    from plane.dumont.access.sync import run_full_sync

    report = run_full_sync()
    # Keep the task result small; the full report is in the logs / the management command.
    return {key: report.get(key) for key in ("status", "mode", "applied", "error") if key in report}
