# Dumont addition: ZITADEL role keys that describe Hangar memberships.
# Not upstream Plane.
#
#   hangar.workspace.admin | hangar.workspace.member | hangar.workspace.guest
#   hangar.project.<identifier lowercase>.admin | .member | .guest   (e.g. hangar.project.mo.member)
#
# Highest role wins (admin 20 > member 15 > guest 5), same numbers as Plane's ROLE enum.
# `hangar_reader` / `hangar_writer` are MCP/API gates, not memberships: they are ignored here.

import re
from dataclasses import dataclass

ADMIN = 20
MEMBER = 15
GUEST = 5

ROLE_BY_NAME = {"admin": ADMIN, "member": MEMBER, "guest": GUEST}
NAME_BY_ROLE = {value: name for name, value in ROLE_BY_NAME.items()}

PREFIX = "hangar."
WORKSPACE_SCOPE = "workspace"
PROJECT_SCOPE = "project"
# The role whose existence marks the workspace as managed (contract: hangar.workspace.member).
WORKSPACE_MANAGED_MARKER = "hangar.workspace.member"

# Plane uppercases identifiers and forbids ".", so a lowercase identifier can never contain the
# separator. We only accept plain ASCII identifiers in role keys, to keep the keys unambiguous.
# Always used with fullmatch: `$` would also accept a trailing newline.
_IDENTIFIER_RE = re.compile(r"[a-z0-9_]{1,12}")


@dataclass(frozen=True)
class RoleKey:
    scope: str  # WORKSPACE_SCOPE or PROJECT_SCOPE
    identifier: str | None  # lowercase project identifier, None for the workspace
    role: int

    @property
    def key(self):
        return role_key(self.scope, self.identifier, self.role)


def role_key(scope, identifier, role):
    name = NAME_BY_ROLE[role]
    if scope == WORKSPACE_SCOPE:
        return f"hangar.workspace.{name}"
    return f"hangar.project.{identifier}.{name}"


def identifier_to_key_part(identifier):
    """Plane project identifier -> the part used in role keys, or None when it cannot be expressed."""
    if not identifier or not isinstance(identifier, str):
        return None
    # ASCII check BEFORE lowercasing: str.lower() maps some non-ASCII letters onto ASCII ones
    # (the Kelvin sign "K" -> "k"), which would let a look-alike identifier take over a role key.
    if not identifier.isascii():
        return None
    part = identifier.strip().lower()
    return part if _IDENTIFIER_RE.fullmatch(part) else None


def parse_role_key(key):
    """Parse a role key. Returns a RoleKey, or None when the key is not a (valid) Hangar membership key.

    Keys are case-sensitive and must be in canonical (lowercase) form; anything else is rejected so
    that two spellings can never describe the same membership.
    """
    if not isinstance(key, str) or not key.startswith(PREFIX):
        return None
    parts = key.split(".")
    if len(parts) == 3 and parts[1] == WORKSPACE_SCOPE and parts[2] in ROLE_BY_NAME:
        return RoleKey(WORKSPACE_SCOPE, None, ROLE_BY_NAME[parts[2]])
    if len(parts) == 4 and parts[1] == PROJECT_SCOPE and parts[3] in ROLE_BY_NAME:
        if _IDENTIFIER_RE.fullmatch(parts[2]):
            return RoleKey(PROJECT_SCOPE, parts[2], ROLE_BY_NAME[parts[3]])
    return None


def is_hangar_key(key):
    return isinstance(key, str) and key.startswith(PREFIX)


def role_name(role):
    return NAME_BY_ROLE.get(role, str(role))
