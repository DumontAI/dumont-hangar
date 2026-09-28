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
# Users without a Dumont login are looked up by e-mail: exactly one match, owned by --org-id
# (details.resourceOwner) with a verified e-mail, or they are skipped and listed. `--apply` prints the
# plan before writing, and every grant update re-reads the grant's current keys right before the PUT.
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
import re
import sys

import requests

EXPORT_FORMAT = "hangar-zitadel-access-export/v1"
# Same string as plane.dumont.auth.config.USER_AGENT (this script cannot import it). Explicit because
# Cloudflare in front of Dumont Auth answers 403 to some library-default User-Agents.
USER_AGENT = "dumont-hangar-api (+https://hangar.getdumont.ai)"
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
            "User-Agent": USER_AGENT,
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

    def search(self, path, queries=None, id_field="id"):
        rows, seen, offset, expected = [], set(), 0, None
        for _ in range(MAX_PAGES):
            body = {"query": {"offset": str(offset), "limit": PAGE_SIZE, "asc": True}}
            if queries:
                body["queries"] = queries
            data = self.request("POST", path, body)
            # Same rules as plane/dumont/access/zitadel.py:
            # - a missing `result` is an empty list only when details.totalResult is present and 0;
            # - the largest totalResult any page announced must be reached; an empty page before it is a
            #   truncated answer; only when no page ever carried a total does a short page end the list;
            # - rows are de-duplicated by id (a row that moved between pages is served twice and another
            #   never), and the distinct count must reach totalResult.
            if not isinstance(data, dict):
                raise BootstrapError(f"POST {path}: response is not a JSON object")
            total = _total_result(data, path)
            if "result" not in data:
                if total != 0:
                    raise BootstrapError(f"POST {path}: response has no 'result' (API shape changed?)")
                page = []
            else:
                page = data["result"]
            if not isinstance(page, list):
                raise BootstrapError(f"POST {path}: 'result' is not a list")
            if total is not None:
                expected = total if expected is None else max(expected, total)
            for row in page:
                row_id = row.get(id_field) if isinstance(row, dict) else None
                if not isinstance(row_id, str) or not row_id:
                    raise BootstrapError(f"POST {path}: row without '{id_field}'")
                if row_id not in seen:
                    seen.add(row_id)
                    rows.append(row)
            offset += len(page)
            if expected is not None:
                if offset >= expected:
                    if len(seen) < expected:
                        raise BootstrapError(
                            f"POST {path}: {len(seen)} distinct rows for totalResult {expected} "
                            "(result shifted during pagination)"
                        )
                    return rows
                if not page:
                    raise BootstrapError(f"POST {path}: empty page at offset {offset} of totalResult {expected}")
            elif len(page) < PAGE_SIZE:
                return rows
        raise BootstrapError(f"POST {path}: too many pages")


def _total_result(data, path):
    """details.totalResult as an int, None when absent; a present but unreadable value is an error."""
    details = data.get("details")
    if not isinstance(details, dict) or "totalResult" not in details:
        return None
    value = details["totalResult"]
    try:
        total = int(value) if not isinstance(value, bool) else -1
    except (TypeError, ValueError):
        total = -1
    if total < 0:
        raise BootstrapError(f"POST {path}: unreadable details.totalResult")
    return total


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


def _resource_owner(row):
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    return details.get("resourceOwner") or None


def _email_verified(row):
    """ZITADEL v1 User: human.email.isEmailVerified (absent means not verified)."""
    human = row.get("human") if isinstance(row.get("human"), dict) else {}
    email = human.get("email") if isinstance(human.get("email"), dict) else {}
    return email.get("isEmailVerified") is True


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
    existing_roles = {
        row.get("key") for row in zitadel.search(f"/management/v1/projects/{project_id}/roles/_search", id_field="key")
    }
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
            # An e-mail match grants access, so it must be unambiguous and trustworthy: the user must be
            # owned by --org-id (explicitly, not just by the org header) and the address verified.
            ids = sorted({m.get("id") for m in matches if isinstance(m, dict) and m.get("id")})
            eligible = sorted(
                {
                    m["id"]
                    for m in matches
                    if isinstance(m, dict)
                    and m.get("id")
                    and _resource_owner(m) == zitadel.org_id
                    and _email_verified(m)
                }
            )
            if len(ids) > 1:
                plan["skipped"].append({"user": who, "reason": "several ZITADEL users match"})
                continue
            if not eligible:
                reason = "not found in ZITADEL"
                if ids:
                    reason = "e-mail match is outside the Dumont organisation or not verified"
                plan["skipped"].append({"user": who, "reason": reason})
                continue
            user_id, resolved_by = eligible[0], "e-mail"
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
                "wanted": keys,
                "role_keys": sorted(current | set(keys)),
                "resolved_by": resolved_by,
            }
        )
    return plan


def current_role_keys(zitadel, project_id, user_id, grant_id):
    """Re-read one grant's role keys right before a PUT (the PUT replaces the whole list)."""
    rows = zitadel.search(
        "/management/v1/users/grants/_search",
        [{"projectIdQuery": {"projectId": project_id}}, {"userIdQuery": {"userId": user_id}}],
    )
    for row in rows:
        if isinstance(row, dict) and row.get("id") == grant_id and row.get("userId") == user_id:
            if _grant_outside_org(row, zitadel.org_id):
                raise BootstrapError("grant is now owned by another organisation; not touched")
            keys = row.get("roleKeys") or []
            if not isinstance(keys, list):
                raise BootstrapError("grant has no roleKeys list")
            return [key for key in keys if isinstance(key, str)]
    raise BootstrapError("grant not found anymore; run the plan again")


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
            # The PUT replaces the grant's whole key list: union with what is there NOW, not with what
            # the plan read, so a key added by someone else in the meantime is never dropped.
            current = current_role_keys(zitadel, project_id, grant["user_id"], grant["grant_id"])
            role_keys = sorted(set(current) | set(grant["wanted"]))
            if role_keys == sorted(set(current)):
                done.append(f"grant update {grant['user']} (already in place)")
                continue
            zitadel.request(
                "PUT",
                f"/management/v1/users/{grant['user_id']}/grants/{grant['grant_id']}",
                {"roleKeys": role_keys},
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
    parser.add_argument("--org-id", default=env.get("DUMONT_ZITADEL_ORG_ID"))
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
    args.org_id = args.org_id.strip()
    # Same rule as DUMONT_ZITADEL_ORG_ID in Hangar (plane/dumont/auth/config.py): a bare id.
    if not args.org_id or re.search(r"[:\s]", args.org_id):
        parser.error("--org-id must be a bare ZITADEL organization id (no ':' or whitespace)")
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
    if not args.json:
        # Show exactly what is about to be written, so the operator's terminal holds the record.
        out.write("APPLYING this plan:\n")
        print_plan(plan, out)
    done, failures = apply_plan(plan, zitadel, args.project_id)
    if args.json:
        out.write(
            json.dumps(
                {"mode": "apply", "plan": plan, "done": done, "failures": failures, "skipped": plan["skipped"]},
                indent=2,
            )
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
