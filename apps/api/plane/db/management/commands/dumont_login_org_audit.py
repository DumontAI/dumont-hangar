# Dumont addition: list Hangar users whose Dumont login (ZITADEL user) is outside the Dumont
# organisation. Not upstream Plane. Read-only: it changes nothing in Hangar or in ZITADEL.
#
#   python manage.py dumont_login_org_audit          # table of outsiders
#   python manage.py dumont_login_org_audit --json   # machine-readable
#
# Run it before DUMONT_WEB_LOGIN_ORG_CHECK=1 (docs/dumont/zitadel-access.md, "Web login organisation
# check"): the check only refuses NEW logins, so outsiders who already have a session or an API token
# keep them until an operator ends them. Uses the sync's read-only service user
# (DUMONT_ACCESS_ZITADEL_KEY_JSON) and DUMONT_ZITADEL_ORG_ID. Prints ids and e-mails, never secrets.
#
# Exit status: 0 no outsider, 3 outsiders listed, 1 error.

import json

from django.core.management import BaseCommand, CommandError


class Command(BaseCommand):
    help = "List Hangar users linked to a ZITADEL user outside DUMONT_ZITADEL_ORG_ID (read-only)"

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true", help="Print the result as JSON")

    def handle(self, *args, **options):
        from plane.db.models import Account, APIToken, Session, User
        from plane.dumont.access.config import AccessConfigError, load_access_config
        from plane.dumont.access.snapshot import DUMONT_PROVIDER
        from plane.dumont.access.sync import make_client
        from plane.dumont.access.zitadel import ZitadelError

        try:
            cfg = load_access_config()
            if cfg.org_id_error:
                raise AccessConfigError(cfg.org_id_error)
            missing = [
                name
                for name, value in (
                    ("DUMONT_ZITADEL_ORG_ID", cfg.org_id),
                    ("DUMONT_ACCESS_ZITADEL_KEY_JSON", cfg.key_source),
                )
                if not value
            ]
            if missing:
                raise AccessConfigError("missing configuration: " + ", ".join(missing))
            links = list(Account.objects.filter(provider=DUMONT_PROVIDER).values_list("user_id", "provider_account_id"))
            subs = sorted({sub for _, sub in links if sub})
            in_org = make_client(cfg).user_ids_in_org(subs) if subs else set()
        except (AccessConfigError, ZitadelError) as exc:
            raise CommandError(f"error: {exc}", returncode=1) from None
        if subs and not in_org:
            # Same guard as the sync: a permission-filtered users/_search (HTTP 200, no rows) would
            # otherwise list everybody as an outsider.
            raise CommandError(
                "error: none of the linked ZITADEL users was found in the organisation "
                "(service user permission too narrow?)",
                returncode=1,
            )

        outsiders = []
        users = {str(u.id): u for u in User.objects.filter(id__in=[uid for uid, _ in links])}
        for user_id, sub in sorted(links, key=lambda item: (str(item[0]), item[1] or "")):
            if sub in in_org:
                continue
            user = users.get(str(user_id))
            outsiders.append(
                {
                    "plane_user_id": str(user_id),
                    "email": user.email if user else None,
                    "zitadel_user_id": sub,
                    "user_active": bool(user and user.is_active),
                    # the user may ALSO have a Dumont login inside the org
                    "has_login_in_org": any(s in in_org for uid, s in links if str(uid) == str(user_id)),
                    "sessions": Session.objects.filter(user_id=str(user_id)).count(),
                    "active_api_tokens": APIToken.objects.filter(user_id=user_id, is_active=True).count(),
                }
            )

        result = {"linked_accounts": len(links), "outsiders": outsiders}
        if options.get("json"):
            self.stdout.write(json.dumps(result, indent=2, sort_keys=True))
        else:
            self.stdout.write(f"Dumont logins checked: {len(links)}; outside the organisation: {len(outsiders)}")
            for item in outsiders:
                self.stdout.write(
                    f"  {item['plane_user_id']}  {item['email']}  zitadel={item['zitadel_user_id']}  "
                    f"active={item['user_active']}  login_in_org={item['has_login_in_org']}  "
                    f"sessions={item['sessions']}  api_tokens={item['active_api_tokens']}"
                )
        if outsiders:
            raise CommandError(f"{len(outsiders)} Dumont login(s) outside the organisation", returncode=3)
