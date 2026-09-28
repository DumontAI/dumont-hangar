# Dumont addition: export current memberships as proposed ZITADEL roles/grants. Not upstream Plane.
# Read-only. Feed the JSON to scripts/dumont/zitadel_access_bootstrap.py.
#
#   python manage.py dumont_access_export --output /tmp/hangar-access.json
#   python manage.py dumont_access_export --format csv

import json

from django.core.management import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Export active memberships as proposed ZITADEL roles and user grants (JSON or CSV)"

    def add_arguments(self, parser):
        parser.add_argument("--workspace", help="Workspace slug (default: DUMONT_ACCESS_WORKSPACE_SLUG)")
        parser.add_argument("--format", choices=["json", "csv"], default="json")
        parser.add_argument("--output", help="Write to this file instead of stdout")

    def handle(self, *args, **options):
        from plane.dumont.access.config import AccessConfigError, load_access_config
        from plane.dumont.access.export import build_export, export_to_csv
        from plane.dumont.access.snapshot import WorkspaceNotFound

        slug = options.get("workspace")
        if not slug:
            try:
                slug = load_access_config().workspace_slug
            except AccessConfigError as exc:
                raise CommandError(str(exc))
        if not slug:
            raise CommandError("pass --workspace or set DUMONT_ACCESS_WORKSPACE_SLUG")
        try:
            export = build_export(slug)
        except WorkspaceNotFound as exc:
            raise CommandError(str(exc))
        text = export_to_csv(export) if options["format"] == "csv" else json.dumps(export, indent=2)
        if options.get("output"):
            with open(options["output"], "w", encoding="utf-8") as handle:
                handle.write(text)
            linked = sum(1 for user in export["users"] if user["linked"])
            self.stdout.write(
                f"wrote {options['output']}: {len(export['roles'])} roles, {len(export['users'])} users "
                f"({linked} with Dumont login), {len(export['skipped'])} skipped"
            )
        else:
            self.stdout.write(text)
