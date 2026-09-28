#!/usr/bin/env python3
# Dumont addition: create the Hangar roles and user grants in ZITADEL from a membership export.
# Not upstream Plane. Stdlib + requests only, so it runs outside the Hangar containers.
#
# Input: the JSON written by `python manage.py dumont_access_export --output FILE`.
# Auth:  a ZITADEL admin Personal Access Token in the environment variable ZITADEL_ADMIN_PAT.
#        The token is only ever sent as a header; it is never printed, logged or written.
#
#   ZITADEL_ADMIN_PAT=... zitadel_access_bootstrap.py export.json \
#       --zitadel-url https://auth.example --project-id <id> --org-id <id>            # plan (default)
#   ZITADEL_ADMIN_PAT=... zitadel_access_bootstrap.py export.json ... --apply --yes    # write
#
# Additive and idempotent: roles are created when missing; a user's grant gets the missing
# hangar.* keys added (existing keys such as hangar_reader are kept); nothing is ever removed.
# Users without a Dumont login are looked up by e-mail (exactly one match or they are skipped).
#
# Run it while DUMONT_ACCESS_SYNC is off or dry-run: creating `hangar.workspace.member` or a
# `hangar.project.<id>.*` role makes that scope managed immediately.
#
# ZITADEL Management API v1 (docs, unverified against the production version):
#   search roles   POST /management/v1/projects/{projectId}/roles/_search
#     https://zitadel.com/docs/apis/resources/mgmt/management-service-list-project-roles
#   add role       POST /management/v1/projects/{projectId}/roles  {roleKey, displayName, group}
#     https://zitadel.com/docs/apis/resources/mgmt/management-service-add-project-role
#   search grants  POST /management/v1/users/grants/_search  (projectIdQuery)
#     https://zitadel.com/docs/apis/resources/mgmt/management-service-list-user-grants
#   add grant      POST /management/v1/users/{userId}/grants  {projectId, roleKeys}
#     https://zitadel.com/docs/apis/resources/mgmt/management-service-add-user-grant
#   update grant   PUT  /management/v1/users/{userId}/grants/{grantId}  {roleKeys}
#     https://zitadel.com/docs/apis/resources/mgmt/management-service-update-user-grant
#   search users   POST /management/v1/users/_search  (emailQuery, TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE)
#     https://zitadel.com/docs/apis/resources/mgmt/management-service-list-users
#   search users   POST /management/v1/users/_search  (inUserIdsQuery {userIds}), org-scoped
#   org context    header x-zitadel-orgid
#
# Organisation boundary (the ZITADEL instance is shared with other products): only users of --org-id
# get grants, and only grants owned by --org-id are updated. A Dumont login of a user from another
# org, or a grant that came through a project grant, is skipped and listed, never written.

import argparse
import json
import os
import sys

import requests

EXPORT_FORMAT = "hangar-zitadel-access-export/v1"
TIMEOUT = 10
PAGE_SIZE = 100
MAX_PAGES = 500


class BootstrapError(Exception):
    pass


class Zitadel:
    def __init__(self, base_url, org_id, pat, session=None):
        self.base_url = base_url.rstrip("/")
        self.org_id = org_id
        self._pat = pat
        self.session = session or requests.Session()

    def __repr__(self):
        return f"Zitadel({self.base_url!r}, org={self.org_id!r}, pat=<redacted>)"

    def request(self, method, path, body=None):
        headers = {
            "Authorization": f"Bearer {self._pat}",
            "x-zitadel-orgid": self.org_id,
            "Accept": "application/json",
        }
        try:
            response = self.session.request(
                method, self.base_url + path, json=body, headers=headers, timeout=TIMEOUT, allow_redirects=False
            )
        except requests.RequestException as exc:
            raise BootstrapError(f"{method} {path}: {exc.__class__.__name__}") from None
        if not 200 <= response.status_code < 300:
            message = ""
            try:
                data = response.json()
                message = str(data.get("message", ""))[:200] if isinstance(data, dict) else ""
            except ValueError:
                pass
            raise BootstrapError(f"{method} {path}: HTTP {response.status_code} {message}".strip())
        try:
            return response.json() if response.content else {}
        except ValueError:
            raise BootstrapError(f"{method} {path}: response is not JSON") from None

    def search(self, path, queries=None):
        rows, offset = [], 0
        for _ in range(MAX_PAGES):
            body = {"query": {"offset": str(offset), "limit": PAGE_SIZE, "asc": True}}
            if queries:
                body["queries"] = queries
            data = self.request("POST", path, body)
            page = data.get("result") or []
            rows.extend(page)
            offset += len(page)
            total = (data.get("details") or {}).get("totalResult")
            if not page:
                return rows
            if total not in (None, ""):
                if offset >= int(total):
                    return rows
            elif len(page) < PAGE_SIZE:
                return rows
        raise BootstrapError(f"POST {path}: too many pages")


def load_export(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or data.get("format") != EXPORT_FORMAT:
        raise BootstrapError(f"{path} is not a {EXPORT_FORMAT} export")
    return data


def _selected(key, projects, skip_workspace):
    if key.startswith("hangar.workspace."):
        return not skip_workspace
    if key.startswith("hangar.project."):
        return projects is None or key.split(".")[2] in projects
    return False


def _grant_outside_org(row, org_id):
    """Same rule as plane/dumont/access/zitadel.py: a project grant or another owner org is foreign."""
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    if row.get("projectGrantId"):
        return True
    return row.get("orgId") not in (None, "", org_id) or details.get("resourceOwner") not in (None, "", org_id)


def users_in_org(zitadel, user_ids):
    """The subset of `user_ids` owned by the org in x-zitadel-orgid (org-scoped users/_search)."""
    wanted = sorted({uid for uid in user_ids if uid})
    found = set()
    for start in range(0, len(wanted), PAGE_SIZE):
        chunk = wanted[start : start + PAGE_SIZE]
        for row in zitadel.search("/management/v1/users/_search", [{"inUserIdsQuery": {"userIds": chunk}}]):
            owner = (row.get("details") or {}).get("resourceOwner")
            if row.get("id") in chunk and owner in (None, "", zitadel.org_id):
                found.add(row["id"])
    return found


def build_plan(export, zitadel, project_id, projects=None, skip_workspace=False):
    """Read ZITADEL and compute what is missing. Performs no writes."""
    roles = [r for r in export["roles"] if _selected(r["key"], projects, skip_workspace)]
    existing_roles = {row.get("key") for row in zitadel.search(f"/management/v1/projects/{project_id}/roles/_search")}
    grants_by_user = {}
    for row in zitadel.search("/management/v1/users/grants/_search", [{"projectIdQuery": {"projectId": project_id}}]):
        if row.get("projectId") not in (None, project_id) or _grant_outside_org(row, zitadel.org_id):
            continue
        grants_by_user.setdefault(row.get("userId"), []).append(row)
    linked_in_org = users_in_org(zitadel, [u.get("zitadel_user_id") for u in export["users"]])

    plan = {
        "roles_to_create": [r for r in roles if r["key"] not in existing_roles],
        "grants_to_create": [],
        "grants_to_update": [],
        "unchanged": 0,
        "skipped": [],
    }
    for user in export["users"]:
        keys = sorted(k for k in user.get("roles", []) if _selected(k, projects, skip_workspace))
        if not keys:
            continue
        who = user.get("email") or user.get("zitadel_user_id")
        user_id = user.get("zitadel_user_id")
        resolved_by = "dumont login"
        if user_id and user_id not in linked_in_org:
            plan["skipped"].append({"user": who, "reason": "Dumont login belongs to another ZITADEL organisation"})
            continue
        if not user_id:
            matches = zitadel.search(
                "/management/v1/users/_search",
                [{"emailQuery": {"emailAddress": user["email"], "method": "TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE"}}],
            )
            ids = sorted({m.get("id") for m in matches if m.get("id")})
            if len(ids) != 1:
                plan["skipped"].append(
                    {"user": who, "reason": "not found in ZITADEL" if not ids else "several ZITADEL users match"}
                )
                continue
            user_id, resolved_by = ids[0], "e-mail"
        grants = grants_by_user.get(user_id, [])
        if len(grants) > 1:
            plan["skipped"].append({"user": who, "reason": "several grants for this project; fix by hand"})
            continue
        if not grants:
            plan["grants_to_create"].append(
                {"user": who, "user_id": user_id, "role_keys": keys, "resolved_by": resolved_by}
            )
            continue
        if grants[0].get("state") not in (None, "", "USER_GRANT_STATE_ACTIVE", "USER_GRANT_STATE_UNSPECIFIED"):
            plan["skipped"].append({"user": who, "reason": "grant is deactivated in ZITADEL; decide by hand"})
            continue
        current = set(grants[0].get("roleKeys") or [])
        missing = sorted(set(keys) - current)
        if not missing:
            plan["unchanged"] += 1
            continue
        plan["grants_to_update"].append(
            {
                "user": who,
                "user_id": user_id,
                "grant_id": grants[0].get("id"),
                "add": missing,
                "role_keys": sorted(current | set(keys)),
                "resolved_by": resolved_by,
            }
        )
    return plan


def apply_plan(plan, zitadel, project_id):
    done, failures = [], []
    for role in plan["roles_to_create"]:
        try:
            zitadel.request(
                "POST",
                f"/management/v1/projects/{project_id}/roles",
                {"roleKey": role["key"], "displayName": role["display_name"], "group": role.get("group", "hangar")},
            )
            done.append(f"role {role['key']}")
        except BootstrapError as exc:
            failures.append(f"role {role['key']}: {exc}")
    if failures:
        # grants need their roles; stop before creating grants against missing roles
        return done, failures
    for grant in plan["grants_to_create"]:
        try:
            zitadel.request(
                "POST",
                f"/management/v1/users/{grant['user_id']}/grants",
                {"projectId": project_id, "roleKeys": grant["role_keys"]},
            )
            done.append(f"grant {grant['user']}")
        except BootstrapError as exc:
            failures.append(f"grant {grant['user']}: {exc}")
    for grant in plan["grants_to_update"]:
        try:
            zitadel.request(
                "PUT",
                f"/management/v1/users/{grant['user_id']}/grants/{grant['grant_id']}",
                {"roleKeys": grant["role_keys"]},
            )
            done.append(f"grant update {grant['user']}")
        except BootstrapError as exc:
            failures.append(f"grant update {grant['user']}: {exc}")
    return done, failures


def print_plan(plan, out):
    out.write(f"roles to create ({len(plan['roles_to_create'])}):\n")
    for role in plan["roles_to_create"]:
        out.write(f"  + {role['key']}  ({role['display_name']})\n")
    out.write(f"grants to create ({len(plan['grants_to_create'])}):\n")
    for grant in plan["grants_to_create"]:
        out.write(f"  + {grant['user']}: {', '.join(grant['role_keys'])}  [by {grant['resolved_by']}]\n")
    out.write(f"grants to extend ({len(plan['grants_to_update'])}):\n")
    for grant in plan["grants_to_update"]:
        out.write(f"  ~ {grant['user']}: add {', '.join(grant['add'])}  [by {grant['resolved_by']}]\n")
    out.write(f"already in place: {plan['unchanged']}\n")
    out.write(f"skipped ({len(plan['skipped'])}):\n")
    for item in plan["skipped"]:
        out.write(f"  ! {item['user']}: {item['reason']}\n")


def main(argv=None, session=None, out=None, env=None):
    out = out or sys.stdout
    env = os.environ if env is None else env
    parser = argparse.ArgumentParser(
        description="Create Hangar roles/grants in ZITADEL from an export (plan by default)"
    )
    parser.add_argument("export", help="JSON from manage.py dumont_access_export")
    parser.add_argument("--zitadel-url", default=env.get("ZITADEL_URL"), help="e.g. https://auth.getdumont.ai")
    parser.add_argument("--project-id", default=env.get("DUMONT_ACCESS_ZITADEL_PROJECT_ID"))
    parser.add_argument("--org-id", default=env.get("DUMONT_ACCESS_ZITADEL_ORG_ID"))
    parser.add_argument("--projects", help="Only these project identifiers (comma separated, e.g. mo,hgr)")
    parser.add_argument("--skip-workspace", action="store_true", help="Leave the hangar.workspace.* roles alone")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true", help="Show what would change (default)")
    mode.add_argument("--apply", action="store_true", help="Write to ZITADEL (requires --yes)")
    parser.add_argument("--yes", action="store_true", help="Confirm --apply")
    parser.add_argument("--json", action="store_true", help="Print the plan/result as JSON")
    args = parser.parse_args(argv)

    missing = [
        n
        for n, v in (("--zitadel-url", args.zitadel_url), ("--project-id", args.project_id), ("--org-id", args.org_id))
        if not v
    ]
    if missing:
        parser.error("missing " + ", ".join(missing))
    pat = env.get("ZITADEL_ADMIN_PAT")
    if not pat:
        parser.error("set ZITADEL_ADMIN_PAT in the environment (it is never printed)")
    if args.apply and not args.yes:
        parser.error("--apply writes to ZITADEL; add --yes to confirm")
    projects = {p.strip().lower() for p in args.projects.split(",") if p.strip()} if args.projects else None

    zitadel = Zitadel(args.zitadel_url, args.org_id, pat, session=session)
    try:
        export = load_export(args.export)
        plan = build_plan(export, zitadel, args.project_id, projects, args.skip_workspace)
    except (BootstrapError, OSError, ValueError) as exc:
        out.write(f"error: {exc}\n")
        return 1
    if not args.apply:
        if args.json:
            out.write(json.dumps({"mode": "plan", **plan}, indent=2) + "\n")
        else:
            out.write("PLAN (nothing written; use --apply --yes to write)\n")
            print_plan(plan, out)
        return 0
    done, failures = apply_plan(plan, zitadel, args.project_id)
    if args.json:
        out.write(
            json.dumps({"mode": "apply", "done": done, "failures": failures, "skipped": plan["skipped"]}, indent=2)
            + "\n"
        )
    else:
        out.write(f"APPLIED {len(done)} change(s)\n")
        for item in done:
            out.write(f"  ok {item}\n")
        for item in failures:
            out.write(f"  FAILED {item}\n")
        for item in plan["skipped"]:
            out.write(f"  skipped {item['user']}: {item['reason']}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
