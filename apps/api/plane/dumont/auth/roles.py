# Dumont addition: Hangar role gate for ZITADEL access tokens.
# Not upstream Plane.
#
# Mirrors mcp/src/auth.ts `hasRole` / `grantedRoles` as of the MCP org-binding backport
# (branch feat/mcp-acts-as-user, commit 2b070bde3), with one difference: where the MCP
# has a single audience project, Plane accepts any of DUMONT_API_AUDIENCES, so `<aud>`
# below means "one of the configured audiences".
#
# Every role is bound to our ZITADEL organization (DUMONT_ZITADEL_ORG_ID). The ZITADEL
# instance is shared: a project can be granted to other organizations, and any org can
# define a role called `hangar_writer`; without the org binding such a token would pass.
#
# Role sources, on a token already bound to our issuer and audience:
# - `urn:zitadel:iam:org:project:<aud>:roles` and `urn:zitadel:iam:org:project:roles`
#   in ZITADEL's object form `{role: {orgId: orgDomain}}`: the role counts only when
#   `claim[role]` is an object that has the allowed org id as a key. A matching
#   resource owner does not rescue a role map granted by another org.
# - Everything that does not say which org granted the role (the array form of those two
#   claims, the legacy flat `roles` claim in either form, and the `my:zitadel:grants`
#   Action claim with its exact `<aud>:<role>` strings): counts only when the token's
#   `urn:zitadel:iam:user:resourceowner:id` is exactly the allowed org id.
#   `org_id` or any other claim never stands in for it.

RESOURCE_OWNER_CLAIM = "urn:zitadel:iam:user:resourceowner:id"
UNSCOPED_PROJECT_CLAIM = "urn:zitadel:iam:org:project:roles"


def _project_claim_names(audiences):
    names = {UNSCOPED_PROJECT_CLAIM}
    names.update(f"urn:zitadel:iam:org:project:{aud}:roles" for aud in audiences)
    return names


def _contains_role(value, role):
    # JS `value === role` on array items: only an equal string matches.
    if isinstance(value, list):
        return any(isinstance(item, str) and item == role for item in value)
    if isinstance(value, dict):
        return role in value
    return False


def has_role(claims, audiences, role, allowed_org_id):
    if not allowed_org_id or not isinstance(allowed_org_id, str):
        return False
    owner_matches = claims.get(RESOURCE_OWNER_CLAIM) == allowed_org_id

    for claim_name in _project_claim_names(audiences):
        value = claims.get(claim_name)
        if isinstance(value, dict):
            orgs = value.get(role)
            if isinstance(orgs, dict) and allowed_org_id in orgs:
                return True
        elif owner_matches and _contains_role(value, role):
            return True

    if not owner_matches:
        return False
    if _contains_role(claims.get("roles"), role):
        return True

    grants = claims.get("my:zitadel:grants")
    if not audiences or not isinstance(grants, list):
        return False
    scoped = {f"{aud}:{role}" for aud in audiences}
    return any(isinstance(grant, str) and grant in scoped for grant in grants)


def granted_roles(claims, audiences, reader_role, writer_role, allowed_org_id):
    """The configured Hangar roles (reader, writer) this token carries for our org, in that order."""
    return tuple(role for role in (reader_role, writer_role) if has_role(claims, audiences, role, allowed_org_id))
