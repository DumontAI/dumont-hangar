# Dumont addition: Hangar role gate for ZITADEL access tokens.
# Not upstream Plane.
#
# Mirrors mcp/src/auth.ts `hasRole` / `grantedRoles` exactly, with one difference the
# contract asks for: where the MCP has a single audience project, Plane accepts any of
# DUMONT_API_AUDIENCES, so `<aud>` below means "one of the configured audiences".
#
# Role sources, on a token already bound to our issuer and audience:
# - `urn:zitadel:iam:org:project:<aud>:roles`: ZITADEL's project-scoped claim.
# - `urn:zitadel:iam:org:project:roles`: roles of the requesting application's project.
# - `roles`: legacy flat claim.
#   For these three: an array containing the role name, or an object with the role as key.
# - `my:zitadel:grants`: custom Action claim; only the exact `<aud>:<role>` string counts,
#   a bare role or another project's role never does.


def _role_claim_names(audiences):
    names = {"roles", "urn:zitadel:iam:org:project:roles"}
    names.update(f"urn:zitadel:iam:org:project:{aud}:roles" for aud in audiences)
    return names


def has_role(claims, audiences, role):
    role_claims = _role_claim_names(audiences)
    for claim_name, claim_value in claims.items():
        if claim_name not in role_claims:
            continue
        # JS `value === role` on array items: only an equal string matches.
        if isinstance(claim_value, list) and any(isinstance(v, str) and v == role for v in claim_value):
            return True
        if isinstance(claim_value, dict) and role in claim_value:
            return True

    grants = claims.get("my:zitadel:grants")
    if not audiences or not isinstance(grants, list):
        return False
    scoped = {f"{aud}:{role}" for aud in audiences}
    return any(isinstance(grant, str) and grant in scoped for grant in grants)


def granted_roles(claims, audiences, reader_role, writer_role):
    """The configured Hangar roles (reader, writer) this token carries, in that order."""
    return tuple(role for role in (reader_role, writer_role) if has_role(claims, audiences, role))
