# Dumont Auth (ZITADEL) bearer tokens on API v1: operator notes

Dumont addition, not upstream Plane. Code: `plane/dumont/auth/`, wired into
`plane/api/views/base.py` (authentication and throttle) and `plane/middleware/logger.py` (audit).

## What it does

With `DUMONT_API_BEARER_ENABLED=1`, API v1 accepts `Authorization: Bearer <ZITADEL access token>`
next to `X-Api-Key`. JWT access tokens are verified locally; opaque access tokens are accepted only
when introspection is configured (see "Opaque access tokens (introspection)"). Sending both headers is refused (400 `DUMONT_AMBIGUOUS_CREDENTIALS`).
The request runs as the Plane user linked to the token `sub` through
`Account(provider="dumont")`; Plane's normal workspace/project permissions then apply.

A token is accepted only when all of this holds:

- compact JWS, RS256, at most 16 KiB, `kid` present, signature valid against the issuer JWKS;
  or, for any other token shape, an introspection answer with `"active": true` (below);
- `iss` equals the issuer, `aud` contains one of `DUMONT_API_AUDIENCES`, `exp` in the future,
  `nbf` (if present) at most 30 s ahead, `sub` present, no `nonce`/`at_hash` (ID tokens);
- the token carries `hangar_reader` or `hangar_writer` **for the organization
  `DUMONT_ZITADEL_ORG_ID`** (see "Organization binding"). Reader-only tokens may only
  use GET/HEAD/OPTIONS;
- the linked Plane user exists, is active and is not a bot.

## Configuration

See `apps/api/.env.example`. When enabled, `DUMONT_API_AUDIENCES` and `DUMONT_ZITADEL_ORG_ID`
are required. The config is parsed while Django settings load, so every container that reads
`apps/api/.env` (api, worker, beat-worker, migrator) refuses to start on an invalid config.
When disabled, every other `DUMONT_API_*` value is ignored.

## Organization binding

A ZITADEL project can be granted to other organizations. A user of such an organization gets a
token for our project with our audience, and without an org check a `hangar_writer` granted in
that other organization would pass. So a role counts only when:

- it comes from `urn:zitadel:iam:org:project:<aud>:roles` or `urn:zitadel:iam:org:project:roles`
  in object form and the role's value is an object with `DUMONT_ZITADEL_ORG_ID` as a key; or
- it comes from a form that does not name the granting org (array form of those claims, the
  legacy `roles` claim, `my:zitadel:grants` as `<aud>:<role>`) **and** the token's
  `urn:zitadel:iam:user:resourceowner:id` equals `DUMONT_ZITADEL_ORG_ID`.

`org_id` or other claims never stand in for the resource owner.

## Responses

| Status | `error_code` | Meaning |
|---|---|---|
| 401 + `WWW-Authenticate: Bearer realm="api", error="invalid_token"` | `DUMONT_INVALID_TOKEN` | token malformed, bad signature, wrong issuer/audience, expired, unknown `kid` |
| 401 + `WWW-Authenticate: Bearer realm="api"` | `DUMONT_ACCOUNT_NOT_LINKED` | no Hangar user linked to this `sub`: sign in once on the web with Dumont login |
| 403 | `DUMONT_HANGAR_ROLE_REQUIRED` | no reader/writer role for our org |
| 403 | `DUMONT_WRITER_ROLE_REQUIRED` | reader-only token on a write method |
| 403 | `DUMONT_USER_NOT_ALLOWED` | linked user is deactivated or a bot |
| 503 | `DUMONT_AUTH_UNAVAILABLE` | the JWKS could not be fetched or was unusable, and the token's `kid` is not in a still-valid cached set; or the introspection call failed (network, timeout, 5xx, our client rejected, unreadable body), is in its 10 s backoff, or this minute's introspection budget is spent |

## Signing keys (JWKS)

- Fetched from `DUMONT_AUTH_JWKS_URL` (same origin as the issuer, no redirects, 5 s timeout,
  256 KiB cap), refreshed every 5 minutes.
- Every request to Dumont Auth (JWKS, introspection, and the membership sync's ZITADEL client and
  bootstrap script) sends `User-Agent: dumont-hangar-api (+https://hangar.getdumont.ai)`
  (`USER_AGENT` in `config.py`). `auth.getdumont.ai` sits behind Cloudflare, which answers 403 to
  urllib's default `Python-urllib/3.x`: without the explicit header every JWKS fetch failed and
  every bearer request got 503 `DUMONT_AUTH_UNAVAILABLE`. Never rely on a library's default.
- A response replaces the cache only if it parses as a JWK Set with at least one RS256 signing
  key with a `kid`; anything else counts as a failed fetch.
- After a failed fetch the issuer is not called again for 10 s. An unknown `kid` forces at most
  one refetch per 60 s.
- While refreshes fail, the last good set keeps verifying the kids it contains for up to 24 h
  after it was fetched. Unknown kids, or any token once that set is older than 24 h or was never
  fetched, get 503.

## Opaque access tokens (introspection)

Some ZITADEL clients (for example the dynamically registered Codex/OpenCode clients the Hangar MCP
serves) get opaque access tokens, which cannot be verified locally. The MCP accepts them through
RFC 7662 introspection and forwards them; Hangar does the same when configured:

- `DUMONT_API_INTROSPECTION_CLIENT_ID` and `DUMONT_API_INTROSPECTION_CLIENT_SECRET`: a ZITADEL API
  application (client_secret_basic) in the project whose tokens are introspected. Introspection is
  on only when both are set; one without the other, or `DUMONT_API_INTROSPECTION_URL` without them,
  refuses to start. The secret is kept out of `repr()`, logs and error messages.
- `DUMONT_API_INTROSPECTION_URL` defaults to `${DUMONT_AUTH_HOST}/oauth/v2/introspect`; same origin
  and https rules as the JWKS URL.

How a bearer is handled:

- A compact JWS (3 base64url segments) always takes the JWKS path above and never reaches the
  issuer, so ID tokens and forged JWTs cannot trigger introspection calls.
- Anything else: 401 `invalid_token` when introspection is off (as before). When it is on, only
  ZITADEL's exact opaque access-token shape is introspected (the same check as the MCP's
  `isZitadelOpaqueToken`): a compact JWE of 5 base64url segments, header `alg` `A256GCMKW`, `enc`
  `A256GCM` and a non-empty `kid`, encrypted key 43 chars, IV 16, tag 22, non-empty ciphertext,
  at most 16 KiB. Any other bearer is 401 `invalid_token` without calling the issuer, so random
  tokens from unauthenticated callers never turn into issuer calls. A matching token is POSTed as
  `token=<t>&token_type_hint=access_token` with HTTP Basic client authentication (id and secret
  form-encoded first, as the MCP does), 5 s timeout, no redirects, 64 KiB response cap.
- HTTP 200 with a JSON object that has `active` and no `error` is an answer. A 4xx other than
  401/403/408/429 means the issuer refused this token: read as inactive (401, cached 30 s).
  Anything else (network error, timeout, redirect, 5xx, 401/403 = our client credentials are
  wrong, 408/429, unreadable or too deeply nested body, a 200 without `active` or with `error`)
  is 503 `DUMONT_AUTH_UNAVAILABLE`, never 401, so clients retry instead of starting a new login.
- `active` must be exactly `true`, otherwise 401 `invalid_token`. `token_type`, when present, must
  be `Bearer`, `access_token` or `urn:ietf:params:oauth:token-type:access_token` (any case).
- Then the same checks as a JWT: `iss`, `aud`, `exp`, `nbf`, `sub`, no `nonce`/`at_hash`, the
  org-bound role gate, the linked account, the method gate, the membership hook and the throttle.
  The role and resource-owner claims must be in the introspection answer, or a valid token gets
  403 `DUMONT_HANGAR_ROLE_REQUIRED`. Which claims ZITADEL returns depends on the introspecting
  application's project and on the scopes the client requested; the MCP relies on the same
  answer, but **at rollout, introspect one real token and check that the role claim is there**
  (this was not verified against production when this was written).
- The audit `token_identifier` is always `dumont:<sub>:sha256:<16 hex>` for an introspected token.

Cache (Django cache, key `dumont_bearer:introspection:v1:<sha256 of the token>`, never the token):
an active answer is reused for `min(60 s, exp - now)`, an inactive one for 30 s, a failure never.
The claim checks run again on every cache hit. A cache outage only costs an extra issuer call.
Revocation in ZITADEL therefore reaches an introspected token within 60 s.

Guards on issuer calls, shared by all processes through the same cache (cache hits never count
and keep working while either guard is active):

- a budget of `DUMONT_API_INTROSPECTION_BUDGET_PER_MINUTE` (default 300) cache misses per
  wall-clock minute (key `dumont_bearer:introspection:budget:<minute>`). Past it, misses get 503
  until the next minute; the log says `introspection budget exhausted` once per minute. If real
  users hit it, raise the budget; if nobody should, someone is sending fresh tokens;
- after a failed call (any 503 cause above), misses get 503 for 10 s without calling the issuer
  (key `dumont_bearer:introspection:backoff`).

A cache outage disables both guards (the call goes through); it never accepts a token.

## Revocation lags until the token expires

JWT access tokens are verified locally (signature and claims); nothing asks ZITADEL whether such a
token was revoked (introspected tokens: see above, at most 60 s). Removing a user's role, deactivating or deleting the user, or ending their session
in ZITADEL takes effect for the API only when the tokens already issued expire (`exp`).
Deactivating the Plane user (`is_active=False`) takes effect immediately (403
`DUMONT_USER_NOT_ALLOWED`).

**At rollout, check the access-token lifetime configured in ZITADEL** (instance/organization
OIDC settings, "Access Token Lifetime") for the client the Hangar MCP uses; that lifetime is the
worst-case revocation delay. It was not verified when this was written.

## Rate limit and audit

- Bearer requests are throttled per `sub` (`DUMONT_API_BEARER_RATE_LIMIT`, default
  `API_KEY_RATE_LIMIT`), with the same `X-RateLimit-*` headers as API keys.
- Authenticated bearer requests are written to `api_activity_logs` like API-key requests, with
  `token_identifier = dumont:<sub>:<jti or sha256 fingerprint>`. The `Authorization` header is
  stored as `[REDACTED]`; the token is never logged or stored.
- Rejections are logged on `plane.authentication.dumont_bearer` with a fixed `reason` code only.
