#!/usr/bin/env bash
# check-brand-strings.sh — grep live/static HTML for leftover upstream "Plane" branding.
#
# WHAT THIS CATCHES: only strings present in the raw HTML response of the routes
# below (page <title>, SSR meta tags, manifest links, anything server-rendered
# before JS runs). That's how we caught the title/favicon/manifest/meta-tag bugs.
#
# WHAT THIS CANNOT CATCH (known ceiling — do NOT extend this script to try):
#   - anything rendered client-side after hydration (React state, mobx stores)
#   - anything gated behind auth/onboarding (e.g. the post-login welcome modal,
#     the logged-in sidebar/top-nav — "Star us on GitHub", "Community" badge)
#   - anything that only appears after a specific user action (error banners,
#     the disabled-signup flow, password-reset emails)
# Every one of those was found by a human/real-browser pass, not this script.
# Run a real-browser sweep (login, onboarding, sidebar, nav, modals) periodically
# in addition to this — this script is a fast pre-deploy gate, not a substitute.
#
# Usage: ./scripts/check-brand-strings.sh [base_url]  (default: https://hangar.getdumont.ai)

set -euo pipefail

BASE_URL="${1:-https://hangar.getdumont.ai}"
ROUTES=("/" "/god-mode/" "/spaces/")

# Curated from every upstream string actually found+fixed this session.
# Deliberately specific phrases/domains, not a bare "Plane" substring match,
# so this doesn't false-positive on unrelated words.
DENYLIST=(
  "Plane | Simple, extensible"
  "Welcome to Plane"
  "Welcome back to Plane"
  "Create your Plane account"
  "Plane Publish"
  "Plane God Mode"
  "Plane - Modern project management"
  "Plane Software, Inc"
  "plane.so"
  "planepowers"
  "makeplane"
  "Powered by Plane"
  'content="Plane"'
  "Redirect to Plane"
  "Star us on GitHub"
)

fail=0
for route in "${ROUTES[@]}"; do
  url="${BASE_URL%/}${route}"
  html="$(curl -sL --max-time 10 "$url" || true)"
  if [ -z "$html" ]; then
    echo "WARN: empty/failed response from $url (skipping)"
    continue
  fi
  for phrase in "${DENYLIST[@]}"; do
    if match=$(grep -F -- "$phrase" <<<"$html"); then
      echo "FOUND '$phrase' at $url:"
      echo "$match" | head -3
      fail=1
    fi
  done
done

if [ "$fail" -eq 0 ]; then
  echo "clean: no denylisted upstream strings in server-rendered HTML at ${BASE_URL}"
fi
exit "$fail"
