# Dumont addition: hook points between Dumont Auth (ZITADEL) and Hangar memberships.
# Not upstream Plane. Owned by the membership sync (Part 2); Part 1 calls on_bearer_authenticated.
#
# Both hooks run a per-user sync (sync.run_user_sync) and NEVER raise into the request path:
# every error is logged and ignored, so a ZITADEL or sync problem can never block a login or an
# API call. In mode `off` they do nothing.

import logging

from django.core.cache import cache

from plane.dumont.access.config import MODE_OFF, current_mode

logger = logging.getLogger("plane.dumont.access")


def _claim(sub, force):
    """At most one per-user sync per sub every 60 s (forced runs still restart the window)."""
    from plane.dumont.access.sync import USER_SYNC_TTL, user_sync_cache_key

    key = user_sync_cache_key(sub)
    if force:
        cache.set(key, 1, USER_SYNC_TTL)
        return True
    return bool(cache.add(key, 1, USER_SYNC_TTL))


def _sync_user(user, sub, force, source):
    try:
        if current_mode() == MODE_OFF or user is None or not sub:
            return None
        try:
            if not _claim(sub, force):
                return None
        except Exception:
            # Without the cache we cannot rate-limit; skip rather than hit ZITADEL on every request.
            logger.warning("dumont access: cache unavailable, per-user sync skipped (%s)", source)
            return None
        from plane.dumont.access.sync import run_user_sync

        return run_user_sync(user, sub)
    except Exception:
        logger.exception("dumont access: per-user sync failed (%s); ignored", source)
        return None


def on_bearer_authenticated(user, sub):
    """Called after a ZITADEL bearer token authenticated `user` (ZITADEL subject `sub`) on API v1.

    Runs the per-user membership sync at most once per 60 s per sub. Never raises.
    """
    _sync_user(user, sub, force=False, source="bearer")
    return None


def on_web_login(user, sub):
    """Called by the Dumont web login callback after a successful login. Never raises.

    Always syncs (a login is rare and the user expects access granted a minute ago to work now).
    """
    _sync_user(user, sub, force=True, source="web_login")
    return None
