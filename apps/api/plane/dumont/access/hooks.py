# Dumont addition: hook points between Dumont Auth (ZITADEL) and Hangar memberships.
# Not upstream Plane.
#
# Part 1 ships this as a no-op stub. Part 2 (ZITADEL as the source of memberships)
# owns this file and replaces the body.


def on_bearer_authenticated(user, sub):
    """Called after a ZITADEL bearer token authenticated `user` (ZITADEL subject `sub`) on API v1.

    Runs after the token, the role gate and the linked Account were all accepted.
    An APIException raised here is returned to the caller; any other exception is
    logged and ignored by the authentication class, so the request still proceeds.
    """
    return None
