# Dumont addition: API activity log identity for ZITADEL bearer requests.
# Not upstream Plane. Used by plane/middleware/logger.py (APITokenLogMiddleware).

from plane.dumont.auth.authentication import AuthContext

# APIActivityLog.token_identifier is a CharField(max_length=255).
TOKEN_IDENTIFIER_MAX_LENGTH = 255


def dumont_bearer_token_identifier(request):
    """`dumont:<sub>:<token_id>` for a request authenticated by a ZITADEL bearer token, else None.

    DRF copies request.auth onto the underlying Django request, which is what the middleware
    sees. token_id is the token's `jti` or a short SHA-256 fingerprint, never the token.
    """
    auth = getattr(request, "auth", None)
    if not isinstance(auth, AuthContext):
        return None
    return f"dumont:{auth.sub}:{auth.token_id}"[:TOKEN_IDENTIFIER_MAX_LENGTH]
