# Dumont addition: sign-in through Dumont Auth (ZITADEL OIDC).
# Not upstream Plane. Keep this file self-contained so upstream merges stay clean.

# Python imports
import logging
import os
from datetime import datetime, timedelta
from urllib.parse import urlencode

import pytz

# Module imports
from plane.authentication.adapter.oauth import OauthAdapter
from plane.dumont.auth.config import USER_AGENT
from plane.license.utils.instance_value import get_configuration_value
from plane.authentication.adapter.error import (
    AUTHENTICATION_ERROR_CODES,
    AuthenticationException,
)

logger = logging.getLogger("plane.authentication")

# Single tenant, single issuer. Overridable only so a staging instance can point elsewhere.
DUMONT_AUTH_HOST = os.environ.get("DUMONT_AUTH_HOST", "https://auth.getdumont.ai").rstrip("/")

# ZITADEL scope that adds the user's organization to the userinfo answer, and the claim it adds.
# https://zitadel.com/docs/apis/openidoauth/scopes (urn:zitadel:iam:user:resourceowner)
RESOURCE_OWNER_SCOPE = "urn:zitadel:iam:user:resourceowner"
RESOURCE_OWNER_ID_CLAIM = "urn:zitadel:iam:user:resourceowner:id"


BASE_SCOPE = "openid email profile"
ORG_CHECK_ENV = "DUMONT_WEB_LOGIN_ORG_CHECK"


def _not_configured():
    return AuthenticationException(
        error_code=AUTHENTICATION_ERROR_CODES["DUMONT_NOT_CONFIGURED"],
        error_message="DUMONT_NOT_CONFIGURED",
    )


def _allowed_org_id():
    """The org a Dumont login must belong to, or "" when the check is off. Read per request.

    Off unless DUMONT_WEB_LOGIN_ORG_CHECK=1 (strict: "1" on, "0"/unset off, anything else refuses
    every Dumont login). When on, DUMONT_ZITADEL_ORG_ID must be a valid bare id, or every Dumont login
    is refused (5113): a broken check fails closed, it never silently turns itself off.
    """
    raw = (os.environ.get(ORG_CHECK_ENV) or "").strip()
    if raw in ("", "0"):
        return ""
    if raw != "1":
        logger.error("Dumont login refused: %s must be 1 or 0/unset", ORG_CHECK_ENV)
        raise _not_configured()
    from plane.dumont.auth.config import BearerConfigError, parse_zitadel_org_id

    try:
        org_id = parse_zitadel_org_id(os.environ)
    except BearerConfigError:
        org_id = ""
    if not org_id:
        logger.error("Dumont login refused: %s=1 needs a valid DUMONT_ZITADEL_ORG_ID", ORG_CHECK_ENV)
        raise _not_configured()
    return org_id


class DumontOAuthProvider(OauthAdapter):
    token_url = f"{DUMONT_AUTH_HOST}/oauth/v2/token"
    userinfo_url = f"{DUMONT_AUTH_HOST}/oidc/v1/userinfo"
    # With the org check off (default) the request is exactly what it was before the check existed.
    scope = BASE_SCOPE
    provider = "dumont"
    # Explicit User-Agent on the token and userinfo calls: Cloudflare in front of Dumont Auth
    # blocks some library-default User-Agents (plane/dumont/auth/README.md).
    request_headers = {"User-Agent": USER_AGENT}

    def __init__(self, request, code=None, state=None, callback=None):
        # Per instance: the resourceowner scope only when the org check is on (raises 5113 when misconfigured).
        self.scope = f"{BASE_SCOPE} {RESOURCE_OWNER_SCOPE}" if _allowed_org_id() else BASE_SCOPE
        (DUMONT_CLIENT_ID, DUMONT_CLIENT_SECRET) = get_configuration_value(
            [
                {
                    "key": "DUMONT_CLIENT_ID",
                    "default": os.environ.get("DUMONT_CLIENT_ID"),
                },
                {
                    "key": "DUMONT_CLIENT_SECRET",
                    "default": os.environ.get("DUMONT_CLIENT_SECRET"),
                },
            ]
        )

        if not (DUMONT_CLIENT_ID and DUMONT_CLIENT_SECRET):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["DUMONT_NOT_CONFIGURED"],
                error_message="DUMONT_NOT_CONFIGURED",
            )

        client_id = DUMONT_CLIENT_ID
        client_secret = DUMONT_CLIENT_SECRET

        redirect_uri = f"""{"https" if request.is_secure() else "http"}://{request.get_host()}/auth/dumont/callback/"""
        url_params = {
            "client_id": client_id,
            "scope": self.scope,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
        }
        auth_url = f"{DUMONT_AUTH_HOST}/oauth/v2/authorize?{urlencode(url_params)}"

        super().__init__(
            request,
            self.provider,
            client_id,
            self.scope,
            redirect_uri,
            auth_url,
            self.token_url,
            self.userinfo_url,
            client_secret,
            code,
            callback=callback,
        )

    def set_token_data(self):
        data = {
            "code": self.code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        token_response = self.get_user_token(data=data)
        # ZITADEL returns expires_in as a duration in seconds, not an absolute timestamp.
        expires_in = token_response.get("expires_in")
        super().set_token_data(
            {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token", None),
                "access_token_expired_at": (
                    datetime.now(tz=pytz.utc) + timedelta(seconds=int(expires_in)) if expires_in else None
                ),
                "refresh_token_expired_at": None,
                "id_token": token_response.get("id_token", ""),
            }
        )

    def set_user_data(self):
        user_info_response = self.get_user_response()
        # Organization boundary. The ZITADEL instance is shared with other products' organizations,
        # and any of their users can complete this OIDC flow. With DUMONT_WEB_LOGIN_ORG_CHECK=1, only
        # users of DUMONT_ZITADEL_ORG_ID may sign in. This runs before complete_login_or_signup, so a
        # refused login never creates a user, never links an Account and never matches by e-mail.
        # The claim comes from the userinfo endpoint (fetched from the issuer with the access token),
        # not from the unverified id_token.
        allowed_org_id = _allowed_org_id()
        if allowed_org_id and user_info_response.get(RESOURCE_OWNER_ID_CLAIM) != allowed_org_id:
            logger.warning("Dumont login refused: user is not in the configured ZITADEL organization")
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["DUMONT_ORG_NOT_ALLOWED"],
                error_message="DUMONT_ORG_NOT_ALLOWED",
            )
        email = user_info_response.get("email")
        # Fail closed exactly like upstream's providers (GHSA-7j95-vh8g-f365): an unverified
        # address would let anyone claim a Hangar account by registering someone else's address
        # at the IdP. Dumont Auth's userinfo does return email_verified, verified against the
        # live endpoint, so an absent claim means something changed and is not safe to trust.
        if not email or user_info_response.get("email_verified") is not True:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OAUTH_PROVIDER_UNVERIFIED_EMAIL"],
                error_message="OAUTH_PROVIDER_UNVERIFIED_EMAIL",
            )
        super().set_user_data(
            {
                "email": email,
                "user": {
                    "avatar": user_info_response.get("picture"),
                    "first_name": user_info_response.get("given_name"),
                    "last_name": user_info_response.get("family_name"),
                    "provider_id": user_info_response.get("sub"),
                    "is_password_autoset": True,
                },
            }
        )
