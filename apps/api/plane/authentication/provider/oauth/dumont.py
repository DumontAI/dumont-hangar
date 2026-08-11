# Dumont addition: sign-in through Dumont Auth (ZITADEL OIDC).
# Not upstream Plane. Keep this file self-contained so upstream merges stay clean.

# Python imports
import os
from datetime import datetime, timedelta
from urllib.parse import urlencode

import pytz

# Module imports
from plane.authentication.adapter.oauth import OauthAdapter
from plane.license.utils.instance_value import get_configuration_value
from plane.authentication.adapter.error import (
    AUTHENTICATION_ERROR_CODES,
    AuthenticationException,
)

# Single tenant, single issuer. Overridable only so a staging instance can point elsewhere.
DUMONT_AUTH_HOST = os.environ.get("DUMONT_AUTH_HOST", "https://auth.getdumont.ai").rstrip("/")


class DumontOAuthProvider(OauthAdapter):
    token_url = f"{DUMONT_AUTH_HOST}/oauth/v2/token"
    userinfo_url = f"{DUMONT_AUTH_HOST}/oidc/v1/userinfo"
    scope = "openid email profile"
    provider = "dumont"

    def __init__(self, request, code=None, state=None, callback=None):
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
        email = user_info_response.get("email")
        # Reject an address the issuer explicitly marks unverified: it would let anyone claim a
        # Hangar account by registering someone else's address at the IdP. Dumont Auth omits
        # email_verified in some responses (same quirk that forced the Frappe oauth.py patch), and
        # a missing claim is not a failed check, so only an explicit false is fatal.
        if not email or user_info_response.get("email_verified") is False:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["DUMONT_OAUTH_PROVIDER_ERROR"],
                error_message="DUMONT_OAUTH_PROVIDER_ERROR",
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
