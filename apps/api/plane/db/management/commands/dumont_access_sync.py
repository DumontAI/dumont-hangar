# Dumont addition: run the ZITADEL -> Hangar membership sync by hand. Not upstream Plane.
# The logic lives in plane/dumont/access/; this file only parses arguments and prints the report.
#
#   python manage.py dumont_access_sync --mode dry-run          # preview, writes nothing
#   python manage.py dumont_access_sync --mode dry-run --json   # machine-readable report
#   python manage.py dumont_access_sync                         # uses DUMONT_ACCESS_SYNC
#   python manage.py dumont_access_sync --max-removals 12       # brake limit for this run only; also
#                                                               # lifts the relative/zero-grants guards
#
# Exit status: 0 ok (including dry-run and mode off), 1 error (nothing written), 2 safety brake.

import json

from django.core.management import BaseCommand, CommandError

from plane.dumont.access.config import MODE_DRY_RUN, MODE_ENFORCE, MODE_OFF


class Command(BaseCommand):
    help = "Sync Hangar workspace/project memberships from ZITADEL grants (see docs/dumont/zitadel-access.md)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--mode",
            choices=[MODE_OFF, MODE_DRY_RUN, MODE_ENFORCE],
            help="Override DUMONT_ACCESS_SYNC for this run (enforce still requires DUMONT_ACCESS_SYNC=enforce)",
        )
        parser.add_argument("--json", action="store_true", help="Print the full report as JSON")
        parser.add_argument(
            "--max-removals",
            type=int,
            default=None,
            metavar="N",
            help="Safety brake for THIS run only: how many distinct users may lose or reduce access "
            "(overrides DUMONT_ACCESS_MAX_REMOVALS). Giving it also lifts, for this run, the relative "
            "brake (more than half of a managed scope) and the 'managed scopes but zero grants' refusal. "
            "Review with --mode dry-run first",
        )

    def handle(self, *args, **options):
        from plane.dumont.access.sync import STATUS_BRAKE, STATUS_BUSY, STATUS_ERROR, run_full_sync

        max_removals = options.get("max_removals")
        if max_removals is not None and max_removals < 0:
            raise CommandError("--max-removals must be >= 0", returncode=1)
        report = run_full_sync(mode=options.get("mode"), max_removals=max_removals)
        if options.get("json"):
            self.stdout.write(json.dumps(report, indent=2, sort_keys=True, default=str))
        else:
            self._print_human(report)
        if report["status"] == STATUS_BRAKE:
            raise CommandError("safety brake: nothing was written", returncode=2)
        if report["status"] in (STATUS_ERROR, STATUS_BUSY):
            raise CommandError(f"{report['status']}: {report.get('error', 'another sync is running')}", returncode=1)

    def _print_human(self, report):
        out = self.stdout.write
        out(f"status: {report['status']}  mode: {report['mode']}")
        if report.get("error"):
            out(f"error: {report['error']}")
        managed = report.get("managed")
        if managed is None:
            return
        out(f"managed workspace: {'yes' if managed['workspace'] else 'no'}")
        out(f"managed projects: {', '.join(managed['projects']) or '-'}")
        for key in ("unknown_project_roles", "invalid_role_keys"):
            if report.get(key):
                out(f"{key}: {', '.join(report[key])}")
        out(f"changes ({len(report['changes'])}):")
        for change in report["changes"]:
            role = f"{change['from_role'] or '-'} -> {change['to_role'] or '-'}"
            cascade = " (cascade)" if change["cascade"] else ""
            who = change["email"] or change["user_id"]
            out(f"  {change['action']:<11} {change['scope']:<12} {who}  {role}{cascade}")
        out(f"pending grants, no Dumont login yet ({len(report['pending'])}):")
        for item in report["pending"]:
            out(f"  {item.get('email') or item['zitadel_user_id']}: {', '.join(item['roles'])}")
        if report["notes"]:
            out(f"notes ({len(report['notes'])}):")
            for note in report["notes"]:
                detail = {k: v for k, v in note.items() if k not in ("kind",)}
                out(f"  {note['kind']}: {detail}")
        if "applied" in report:
            out(
                f"applied: {report['applied']}  stale: {len(report['stale'])}  failed scopes: {report['failed_scopes']}"
            )
        if report.get("cascaded"):
            out(f"cascaded into other projects ({len(report['cascaded'])}; not reverted automatically):")
            for change in report["cascaded"]:
                out(f"  {change['action']:<11} {change['scope']:<12} {change['user_id']}  {change['from_role']}")
        if report.get("identifier_collisions"):
            out(f"identifier collisions (left unmanaged): {report['identifier_collisions']}")
        for item in report.get("relative_brake") or []:
            out(f"relative brake: {item['scope']} would lose {item['losing']} of {item['members']} members")
        for reason in report.get("would_refuse") or []:
            out(f"enforce would refuse: {reason} (explicit --max-removals overrides)")
        if report["status"] == "aborted_brake":
            out(
                f"SAFETY BRAKE: {report['counts']['users_losing_access']} users would lose or reduce access "
                f"> {report.get('max_removals')}"
            )
