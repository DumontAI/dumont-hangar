# Dumont addition: per-user rate limit for ZITADEL bearer requests on API v1.
# Not upstream Plane.

from django.conf import settings

from plane.api.rate_limit import ApiKeyRateThrottle
from plane.dumont.auth.authentication import AuthContext


class DumontBearerRateThrottle(ApiKeyRateThrottle):
    """Throttles bearer requests per ZITADEL `sub` (scope `dumont_bearer`).

    Inherits the X-RateLimit-Remaining / X-RateLimit-Reset bookkeeping of the API key
    throttle. Requests that were not authenticated by a bearer token are not counted here.
    """

    scope = "dumont_bearer"
    # None makes SimpleRateThrottle.__init__ call get_rate(), read from settings per instance.
    rate = None

    def get_rate(self):
        return settings.DUMONT_API_BEARER.rate_limit

    def get_cache_key(self, request, view):
        auth = getattr(request, "auth", None)
        if not isinstance(auth, AuthContext):
            return None
        return f"{self.scope}:{auth.sub}"

    def allow_request(self, request, view):
        # Not a bearer request: leave the X-RateLimit headers the API key throttle set alone
        # (the parent class would overwrite them even without a cache key).
        if self.get_cache_key(request, view) is None:
            return True
        allowed = super().allow_request(request, view)
        if not allowed:
            # The API key throttle (no key on a bearer request) already wrote placeholder
            # headers for this request; replace them with the real state.
            request.META["X-RateLimit-Remaining"] = 0
            request.META["X-RateLimit-Reset"] = int(self.now + (self.wait() or 0))
        return allowed
