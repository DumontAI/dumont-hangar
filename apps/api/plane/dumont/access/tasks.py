# Dumont addition: Celery beat entry point of the ZITADEL -> Hangar membership sync.
# Not upstream Plane. Scheduled every 5 minutes in plane/celery.py; a no-op in mode `off`.

from celery import shared_task

from plane.dumont.access.config import MODE_OFF, current_mode


@shared_task(name="plane.dumont.access.tasks.dumont_access_full_sync", ignore_result=True)
def dumont_access_full_sync():
    if current_mode() == MODE_OFF:
        return {"status": "off"}
    from plane.dumont.access.sync import run_full_sync

    report = run_full_sync()
    # Keep the task result small; the full report is in the logs / the management command.
    return {key: report.get(key) for key in ("status", "mode", "applied", "error") if key in report}
