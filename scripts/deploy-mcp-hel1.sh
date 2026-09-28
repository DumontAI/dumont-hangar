#!/usr/bin/env bash
# Install one immutable Hangar MCP release on airbase-hel1 (run by the
# `hangar-mcp.yml` deploy job on a self-hosted runner that lives on hel1).
#
#   bash scripts/deploy-mcp-hel1.sh <release.tar.gz> <release-id>
#
# The caller supplies configuration and secrets through HANGAR_MCP_* environment
# variables (GitHub environment `production`). This script never prints a value:
# only key names, HTTP status codes and outcome classes.
#
# Steps: validate inputs -> stage + `pnpm install --prod` -> validate the runtime
# config with the release's own loader -> (optional) introspection self-check ->
# refuse to silently drop keys from the current env file -> move the release to
# releases/<id> -> write /etc/dumont-hangar-mcp.env (root:deploy 0640, previous
# copy kept root-only) -> install the unit -> switch `current` -> restart ->
# loopback 401 check. Any failure after the switch restores the previous release
# AND the previous env file, then restarts.
set -euo pipefail

ARCHIVE="${1:-}"
RELEASE_ID="${2:-}"
# The unit file hard-codes this path, so it is not configurable here.
APP_ROOT="/opt/dumont-hangar-mcp"
SERVICE_NAME="dumont-hangar-mcp.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
ENV_PATH="/etc/dumont-hangar-mcp.env"
ENV_PREVIOUS="/etc/dumont-hangar-mcp.env.previous"
UNIT_SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/mcp/deploy/dumont-hangar-mcp.service"
NODE_BIN=/usr/bin/node
PNPM_BIN="${PNPM_BIN:-$(command -v pnpm || true)}"

HTTP_PORT="${HANGAR_MCP_HTTP_PORT:-3014}"
BASE_URL="${HANGAR_MCP_BASE_URL:-https://hangar.getdumont.ai}"
WORKSPACE_SLUG="${HANGAR_MCP_WORKSPACE_SLUG:-}"
ALLOWED_PROJECTS="${HANGAR_MCP_ALLOWED_PROJECTS:-}"
WRITE_PROJECTS="${HANGAR_MCP_WRITE_PROJECTS:-}"
WRITE_RATE_LIMIT="${HANGAR_MCP_WRITE_RATE_LIMIT:-}"
TIMEOUT_MS="${HANGAR_MCP_TIMEOUT_MS:-}"
MAX_RESPONSE_BYTES="${HANGAR_MCP_MAX_RESPONSE_BYTES:-}"
MAX_SEARCH_PAGES="${HANGAR_MCP_MAX_SEARCH_PAGES:-}"
PROJECT_CACHE_SECONDS="${HANGAR_MCP_PROJECT_CACHE_SECONDS:-}"
ALLOWED_HOSTS="${HANGAR_MCP_ALLOWED_HOSTS:-}"
ALLOWED_ORIGINS="${HANGAR_MCP_ALLOWED_ORIGINS:-}"
RESOURCE_URL="${HANGAR_MCP_RESOURCE_URL:-}"
OIDC_ISSUER="${HANGAR_MCP_OIDC_ISSUER:-}"
OIDC_JWKS_URL="${HANGAR_MCP_OIDC_JWKS_URL:-}"
OIDC_AUDIENCE="${HANGAR_MCP_OIDC_AUDIENCE:-}"
OIDC_READER_ROLE="${HANGAR_MCP_OIDC_READER_ROLE:-hangar_reader}"
OIDC_WRITER_ROLE="${HANGAR_MCP_OIDC_WRITER_ROLE:-hangar_writer}"
OIDC_REQUIRED_SCOPE="${HANGAR_MCP_OIDC_REQUIRED_SCOPE:-}"
OIDC_ALLOWED_ORG_ID="${HANGAR_MCP_OIDC_ALLOWED_ORG_ID:-}"
OIDC_ALLOWED_SUBJECTS="${HANGAR_MCP_OIDC_ALLOWED_SUBJECTS:-}"
OIDC_INTROSPECTION_URL="${HANGAR_MCP_OIDC_INTROSPECTION_URL:-}"
OIDC_INTROSPECTION_CLIENT_ID="${HANGAR_MCP_OIDC_INTROSPECTION_CLIENT_ID:-}"
OIDC_INTROSPECTION_TIMEOUT_MS="${HANGAR_MCP_OIDC_INTROSPECTION_TIMEOUT_MS:-}"
OIDC_INTROSPECTION_CACHE_SECONDS="${HANGAR_MCP_OIDC_INTROSPECTION_CACHE_SECONDS:-}"
OIDC_INTROSPECTION_MAX_IN_FLIGHT="${HANGAR_MCP_OIDC_INTROSPECTION_MAX_IN_FLIGHT:-}"
OIDC_INTROSPECTION_RATE_PER_SECOND="${HANGAR_MCP_OIDC_INTROSPECTION_RATE_PER_SECOND:-}"
# Secrets.
HANGAR_API_KEY="${HANGAR_MCP_API_KEY:-}"
OIDC_INTROSPECTION_CLIENT_SECRET="${HANGAR_MCP_OIDC_INTROSPECTION_CLIENT_SECRET:-}"
OIDC_INTROSPECTION_PRIVATE_KEY_JSON="${HANGAR_MCP_OIDC_INTROSPECTION_PRIVATE_KEY_JSON:-}"
# Set to "true" only after reading the key-name diff this script prints.
ALLOW_ENV_KEY_DROP="${HANGAR_MCP_ALLOW_ENV_KEY_DROP:-false}"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ -n "$ARCHIVE" && -f "$ARCHIVE" ]] || die "release archive is required"
[[ "$RELEASE_ID" =~ ^[A-Za-z0-9._-]{8,160}$ ]] || die "release id has an invalid format"
[[ -x "$NODE_BIN" ]] || die "/usr/bin/node (used by ${SERVICE_NAME}) was not found"
NODE_MAJOR="$("$NODE_BIN" -p 'process.versions.node.split(".")[0]')"
[[ "$NODE_MAJOR" =~ ^[0-9]+$ && "$NODE_MAJOR" -ge 20 ]] || die "/usr/bin/node must be Node 20 or newer"
[[ -n "$PNPM_BIN" && -x "$PNPM_BIN" ]] || die "pnpm binary was not found"
[[ -f "$UNIT_SOURCE" ]] || die "systemd unit file is missing from the checkout"
[[ "$HTTP_PORT" =~ ^[1-9][0-9]{0,4}$ && "$HTTP_PORT" -le 65535 ]] || die "HANGAR_MCP_HTTP_PORT is invalid"
# The service binds 127.0.0.1 and Caddy proxies with the public Host header, so
# an empty list would reject every proxied request. Copy the current value.
[[ -n "$ALLOWED_HOSTS" ]] || die "HANGAR_MCP_ALLOWED_HOSTS is required (copy it from the current ${ENV_PATH})"
IFS=',' read -r -a ALLOWED_HOST_VALUES <<< "$ALLOWED_HOSTS"
for allowed_host in "${ALLOWED_HOST_VALUES[@]}"; do
  normalized_host="${allowed_host// /}"
  if [[ "$normalized_host" == \[*\] ]]; then
    normalized_host="${normalized_host#[}"
    normalized_host="${normalized_host%]}"
  fi
  [[ -n "$normalized_host" && "$normalized_host" != *[!A-Za-z0-9._:-]* ]] || die "HANGAR_MCP_ALLOWED_HOSTS is invalid"
done
[[ "$HANGAR_API_KEY" =~ ^plane_api_[0-9a-f]{32}$ ]] || die "HANGAR_MCP_API_KEY must be a Hangar API token (plane_api_ + 32 lowercase hex)"
for name in OIDC_INTROSPECTION_CLIENT_SECRET OIDC_INTROSPECTION_PRIVATE_KEY_JSON ALLOWED_PROJECTS WRITE_PROJECTS \
  OIDC_ALLOWED_SUBJECTS ALLOWED_ORIGINS; do
  case "${!name}" in
    *$'\n'*|*$'\r'*) die "HANGAR_MCP_${name} must be a single line (use jq -c for the key JSON)" ;;
  esac
done
case "$BASE_URL" in
  https://*|http://127.0.0.1*|http://localhost*|http://\[::1\]*) ;;
  *) die "HANGAR_MCP_BASE_URL must use HTTPS or loopback HTTP" ;;
esac
[[ "$ALLOW_ENV_KEY_DROP" == "true" || "$ALLOW_ENV_KEY_DROP" == "false" ]] || die "HANGAR_MCP_ALLOW_ENV_KEY_DROP must be true or false"

tar -tzf "$ARCHIVE" >/dev/null || die "release archive is invalid"
# Do not use grep -q here: with pipefail, grep can close the pipe early and
# make tar report SIGPIPE as a false validation failure.
tar -tzf "$ARCHIVE" | grep -Fx 'mcp/dist/http.js' >/dev/null || die "release archive has no HTTP entrypoint"
tar -tzf "$ARCHIVE" | grep -Fx 'mcp/package.json' >/dev/null || die "release archive has no package manifest"
tar -tzf "$ARCHIVE" | grep -Fx 'mcp/pnpm-lock.yaml' >/dev/null || die "release archive has no lockfile"

sudo install -d -o deploy -g deploy -m 0750 "$APP_ROOT" "$APP_ROOT/releases"
STAGING_DIR="$(mktemp -d "$APP_ROOT/releases/.staging.XXXXXX")"
ENV_TMP=""
CURRENT_TMP=""
cleanup() {
  if [[ -n "${STAGING_DIR:-}" && -d "$STAGING_DIR" ]]; then
    rm -rf -- "$STAGING_DIR"
  fi
  if [[ -n "${ENV_TMP:-}" && -f "$ENV_TMP" ]]; then
    rm -f -- "$ENV_TMP"
  fi
  if [[ -n "${CURRENT_TMP:-}" && -L "$CURRENT_TMP" ]]; then
    rm -f -- "$CURRENT_TMP"
  fi
}
trap cleanup EXIT

tar -xzf "$ARCHIVE" -C "$STAGING_DIR"
[[ -f "$STAGING_DIR/mcp/dist/http.js" ]] || die "extracted release is incomplete"

echo "==> installing production dependencies for ${RELEASE_ID}"
"$PNPM_BIN" --dir "$STAGING_DIR/mcp" install --prod --frozen-lockfile --ignore-scripts --ignore-workspace

# One list, used for validation and for the env file, so both see the same keys.
runtime_env() {
  printf '%s\0' \
    "HANGAR_BASE_URL=$BASE_URL" \
    "HANGAR_API_KEY=$HANGAR_API_KEY" \
    "HANGAR_WORKSPACE_SLUG=$WORKSPACE_SLUG" \
    "HANGAR_ALLOWED_PROJECTS=$ALLOWED_PROJECTS" \
    "HANGAR_WRITE_PROJECTS=$WRITE_PROJECTS" \
    "HANGAR_WRITE_RATE_LIMIT=$WRITE_RATE_LIMIT" \
    "HANGAR_TIMEOUT_MS=$TIMEOUT_MS" \
    "HANGAR_MAX_RESPONSE_BYTES=$MAX_RESPONSE_BYTES" \
    "HANGAR_MAX_SEARCH_PAGES=$MAX_SEARCH_PAGES" \
    "HANGAR_PROJECT_CACHE_SECONDS=$PROJECT_CACHE_SECONDS" \
    "MCP_HTTP_HOST=127.0.0.1" \
    "MCP_HTTP_PORT=$HTTP_PORT" \
    "MCP_AUTH_MODE=oidc" \
    "MCP_ALLOWED_HOSTS=$ALLOWED_HOSTS" \
    "MCP_ALLOWED_ORIGINS=$ALLOWED_ORIGINS" \
    "MCP_RESOURCE_URL=$RESOURCE_URL" \
    "MCP_OIDC_ISSUER=$OIDC_ISSUER" \
    "MCP_OIDC_JWKS_URL=$OIDC_JWKS_URL" \
    "MCP_OIDC_AUDIENCE=$OIDC_AUDIENCE" \
    "MCP_OIDC_READER_ROLE=$OIDC_READER_ROLE" \
    "MCP_OIDC_WRITER_ROLE=$OIDC_WRITER_ROLE" \
    "MCP_OIDC_REQUIRED_SCOPE=$OIDC_REQUIRED_SCOPE" \
    "MCP_OIDC_ALLOWED_ORG_ID=$OIDC_ALLOWED_ORG_ID" \
    "MCP_OIDC_ALLOWED_SUBJECTS=$OIDC_ALLOWED_SUBJECTS" \
    "MCP_OIDC_INTROSPECTION_URL=$OIDC_INTROSPECTION_URL" \
    "MCP_OIDC_INTROSPECTION_CLIENT_ID=$OIDC_INTROSPECTION_CLIENT_ID" \
    "MCP_OIDC_INTROSPECTION_CLIENT_SECRET=$OIDC_INTROSPECTION_CLIENT_SECRET" \
    "MCP_OIDC_INTROSPECTION_PRIVATE_KEY_JSON=$OIDC_INTROSPECTION_PRIVATE_KEY_JSON" \
    "MCP_OIDC_INTROSPECTION_TIMEOUT_MS=$OIDC_INTROSPECTION_TIMEOUT_MS" \
    "MCP_OIDC_INTROSPECTION_CACHE_SECONDS=$OIDC_INTROSPECTION_CACHE_SECONDS" \
    "MCP_OIDC_INTROSPECTION_MAX_IN_FLIGHT=$OIDC_INTROSPECTION_MAX_IN_FLIGHT" \
    "MCP_OIDC_INTROSPECTION_RATE_PER_SECOND=$OIDC_INTROSPECTION_RATE_PER_SECOND"
}

run_with_runtime_env() {
  local -a assignments=()
  while IFS= read -r -d '' assignment; do
    assignments+=("$assignment")
  done < <(runtime_env)
  (cd "$STAGING_DIR" && env -i PATH="$PATH" "${assignments[@]}" "$@")
}

echo "==> validating runtime configuration"
run_with_runtime_env "$NODE_BIN" --input-type=module -e "
  const { loadHangarConfig, assertHttpAuthConfigured } = await import('./mcp/dist/config.js');
  try {
    const config = loadHangarConfig();
    assertHttpAuthConfigured(config);
    console.log('OK: configuration valid; write projects=' + config.writeProjects.length + ', write rate limit=' + config.writeRateLimit + '/min');
  } catch (error) {
    console.error('ERROR: ' + (error && error.message ? error.message : 'invalid configuration'));
    process.exit(1);
  }
" || die "runtime configuration is invalid"

if [[ -n "$OIDC_INTROSPECTION_URL" ]]; then
  # A fixed dummy JWE must come back as HTTP 200 {"active":false}. Only the
  # outcome class and HTTP status are printed, never the credentials.
  echo "==> checking OIDC introspection client authentication"
  run_with_runtime_env "$NODE_BIN" --input-type=module -e "
    const { loadHangarConfig } = await import('./mcp/dist/config.js');
    const { introspectionSelfCheck } = await import('./mcp/dist/introspection.js');
    const result = await introspectionSelfCheck(loadHangarConfig());
    if (!result.ok) {
      console.error('ERROR: introspection self-check failed: reason=' + result.reason + ' status=' + (result.httpStatus ?? 'none'));
      process.exit(1);
    }
    console.log('OK: introspection client authentication accepted (HTTP ' + result.httpStatus + ', active=false)');
  " || die "OIDC introspection self-check failed; check the API application credentials"
fi

systemd_quote() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "$value"
}
ENV_TMP="$(mktemp)"
chmod 0600 "$ENV_TMP"
while IFS= read -r -d '' assignment; do
  printf '%s=%s\n' "${assignment%%=*}" "$(systemd_quote "${assignment#*=}")"
done < <(runtime_env) > "$ENV_TMP"

# The env file used to be hand-written. Refuse to drop a key it sets unless the
# operator acknowledged the key-name diff (names only, never values).
if sudo test -f "$ENV_PATH"; then
  existing_keys="$(sudo sed -n 's/^[[:space:]]*\(export[[:space:]]\+\)\?\([A-Za-z_][A-Za-z0-9_]*\)=.*/\2/p' "$ENV_PATH" | sort -u)"
  new_keys="$(sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' "$ENV_TMP" | sort -u)"
  # MCP_OIDC_REQUIRED_ROLE was renamed to MCP_OIDC_READER_ROLE (HGR-6).
  dropped="$(comm -23 <(printf '%s\n' "$existing_keys") <(printf '%s\n' "$new_keys") \
    | sed -e '/^$/d' -e '/^MCP_OIDC_REQUIRED_ROLE$/d' || true)"
  if [[ -n "$dropped" ]]; then
    echo "Keys set in ${ENV_PATH} that this deploy would drop:" >&2
    printf '  %s\n' $dropped >&2
    [[ "$ALLOW_ENV_KEY_DROP" == "true" ]] || die "refusing to drop env keys; map them to HANGAR_MCP_* variables or set HANGAR_MCP_ALLOW_ENV_KEY_DROP=true"
    echo "WARN: dropping them because HANGAR_MCP_ALLOW_ENV_KEY_DROP=true" >&2
  fi
fi

RELEASE_DIR="$APP_ROOT/releases/$RELEASE_ID"
if [[ -e "$RELEASE_DIR" ]]; then
  die "release already exists; use a unique release id instead of overwriting it"
fi
mv "$STAGING_DIR" "$RELEASE_DIR"
STAGING_DIR=""
chown -R deploy:deploy "$RELEASE_DIR"
chmod 0750 "$RELEASE_DIR" "$RELEASE_DIR/mcp"
find "$RELEASE_DIR/mcp" -type f -exec chmod 0640 {} +
chmod 0750 "$RELEASE_DIR/mcp/dist/http.js"
printf 'release_id=%s\nsource_commit=%s\nsource_ref=%s\n' \
  "$RELEASE_ID" "${GITHUB_SHA:-unknown}" "${GITHUB_REF:-unknown}" > "$RELEASE_DIR/RELEASE"
chmod 0640 "$RELEASE_DIR/RELEASE"

HAD_PREVIOUS_ENV=false
if sudo test -f "$ENV_PATH"; then
  sudo install -o root -g root -m 0600 "$ENV_PATH" "$ENV_PREVIOUS"
  HAD_PREVIOUS_ENV=true
fi
sudo install -o root -g deploy -m 0640 "$ENV_TMP" "$ENV_PATH"
rm -f -- "$ENV_TMP"
ENV_TMP=""

sudo install -o root -g root -m 0644 "$UNIT_SOURCE" "$SERVICE_PATH"

OLD_TARGET=""
if [[ -L "$APP_ROOT/current" ]]; then
  OLD_TARGET="$(readlink -f "$APP_ROOT/current" 2>/dev/null || true)"
  [[ -d "$OLD_TARGET" ]] || OLD_TARGET=""
fi
switch_current() {
  local target="$1"
  CURRENT_TMP="$APP_ROOT/.current.${RELEASE_ID}.$$"
  ln -s "$target" "$CURRENT_TMP"
  mv -Tf "$CURRENT_TMP" "$APP_ROOT/current"
  CURRENT_TMP=""
}
rollback() {
  echo "==> rolling back to the previous release and env file" >&2
  if [[ "$HAD_PREVIOUS_ENV" == true ]]; then
    sudo install -o root -g deploy -m 0640 "$ENV_PREVIOUS" "$ENV_PATH" || true
  fi
  if [[ -n "$OLD_TARGET" && -d "$OLD_TARGET" ]]; then
    switch_current "$OLD_TARGET"
    sudo systemctl restart "$SERVICE_NAME" || true
  else
    sudo systemctl stop "$SERVICE_NAME" || true
  fi
  sudo journalctl -u "$SERVICE_NAME" -n 20 --no-pager >&2 || true
}
switch_current "$RELEASE_DIR"

echo "==> restarting ${SERVICE_NAME}"
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME" >/dev/null
if ! sudo systemctl restart "$SERVICE_NAME"; then
  rollback
  die "MCP service failed to restart"
fi

for attempt in 1 2 3 4 5 6; do
  status="$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${HTTP_PORT}/mcp" || true)"
  if [[ "$status" == 401 ]]; then
    echo "OK: MCP loopback endpoint is up and rejects unauthenticated requests (HTTP 401, attempt ${attempt})"
    exit 0
  fi
  sleep 2
done

rollback
die "MCP loopback endpoint did not become ready"
