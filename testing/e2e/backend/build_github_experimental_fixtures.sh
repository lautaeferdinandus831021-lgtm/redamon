#!/usr/bin/env bash
# Build the fixtures the `github_experimental` source matrix measures against.
#
# SYNTHETIC credentials only. Every value below is fabricated and was verified to
# FIRE its detector against the pinned TruffleHog 3.96.0 binary before being
# pushed anywhere. None is, or ever was, a real credential.
#
# CREATE-ONLY. This script never deletes a repository and has no destroy mode:
# a fixture builder that can delete is one typo away from removing real work.
#
# What makes this fixture set different from build_github_fixtures.sh: the whole
# point of `github_experimental` is finding secrets in commits that are NO LONGER
# REACHABLE from any ref. So the interesting fixture cannot be created by writing
# a file - it has to be manufactured by pushing a commit and then force-pushing
# it out of the branch, leaving the object dangling on GitHub's servers.
#
#   whitehat-thx-dangling   live tree CLEAN; SentryToken ONLY in an unreachable
#                          commit, recorded in the manifest as `danglingSha`
#   whitehat-thx-live       an RSA PrivateKey in the live tree, nothing dangling
#
# That contrast is the proof: scanning the dangling repo with the ordinary
# `github` source finds NOTHING, and with `github_experimental` finds
# SentryToken. The zero half is what shows the source does something no other
# source can.
#
# WHY THESE TWO DETECTORS, and not the SendGrid/Mailgun pair the github fixtures
# use. Object discovery needs the repo to be PUBLIC, and GitHub enforces secret
# scanning PUSH PROTECTION on every public push. The repo-level setting can be
# turned off through the API (relax_push_protection below), but the account-level
# "push protection for users" switch cannot - it has no API at all - so a fixture
# builder that needs a human to click an unblock link once per secret is not a
# builder. Probed against the live service on 2026-08-19: SendGrid, Shippo and
# Linear are rejected; SentryToken and an `openssl genrsa` PrivateKey are not.
# If GitHub adds a pattern for one of these, the push fails loudly with GH013 and
# the fix is to probe for a new pair, not to weaken the account's settings.
#
# Both repos also carry AWS's published example key pair as a NEGATIVE CONTROL.
# TruffleHog does not flag it (the AWS detector checksum-validates the key id),
# so a fixture set that reported it would be flagging everything.
#
# Idempotent, and self-healing against GitHub's garbage collector: if the
# recorded dangling SHA no longer resolves, a fresh dangling commit is minted and
# the branch is put back exactly where it was. Nothing else is touched.
#
# NEVER PUSH A THROWAWAY BRANCH TO THE DANGLING REPO. Deleting the branch
# afterwards does NOT undo it: the objects stay on GitHub's servers and become
# exactly the kind of unreachable commit this source is built to find, so they
# turn up in every future scan forever. That already happened once, on
# 2026-08-19, while probing which detectors survive push protection - commit
# 9499a750 (`sentry.env`, `deploy_key.pem`) is permanently discoverable here and
# adds two findings nobody planted. Probe on a scratch repo instead.
#
# The assertions are written to tolerate it: the matrix requires the RECORDED
# SHA to be among the findings rather than requiring the finding set to be
# exactly one. A fixture whose extra findings are load-bearing would be a
# fixture that rots.
#
# Usage:  testing/e2e/backend/build_github_experimental_fixtures.sh
# Token:  _local/gh_fixture_token, or $GITHUB_FIXTURE_TOKEN. Needs `repo`.
# Writes: _local/github_experimental_fixtures.json
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORK="$ROOT/_local/ghx_fixture_build"
MANIFEST="$ROOT/_local/github_experimental_fixtures.json"
PREFIX="${WHITEHAT_FIXTURE_PREFIX:-whitehat-thx}"
TH_IMAGE="${WHITEHAT_TRUFFLEHOG_IMAGE:-whitehat-trufflehog:latest}"

TOKEN="${GITHUB_FIXTURE_TOKEN:-}"
if [[ -z "$TOKEN" && -f "$ROOT/_local/gh_fixture_token" ]]; then
  TOKEN="$(tr -d '[:space:]' < "$ROOT/_local/gh_fixture_token")"
fi
if [[ -z "$TOKEN" ]]; then
  echo "no token: set GITHUB_FIXTURE_TOKEN or write _local/gh_fixture_token" >&2
  exit 2
fi

API="https://api.github.com"

# `set -e` plus a failing curl inside a command substitution would abort with no
# context, so every call reports its own status and the caller decides.
api() {
  local method="$1" path="$2" body="${3:-}"
  local -a args=(-sS -X "$method"
    -H "Authorization: Bearer $TOKEN"
    -H "Accept: application/vnd.github+json"
    -H "X-GitHub-Api-Version: 2022-11-28")
  [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" -d "$body")
  curl "${args[@]}" "$API$path"
}

api_code() {
  local method="$1" path="$2" body="${3:-}"
  local -a args=(-sS -o /dev/null -w '%{http_code}' -X "$method"
    -H "Authorization: Bearer $TOKEN"
    -H "Accept: application/vnd.github+json"
    -H "X-GitHub-Api-Version: 2022-11-28")
  [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" -d "$body")
  curl "${args[@]}" "$API$path"
}

OWNER="$(api GET /user | jq -r .login)"
if [[ -z "$OWNER" || "$OWNER" == "null" ]]; then
  echo "token did not authenticate" >&2
  exit 2
fi

DANGLING="$PREFIX-dangling"
LIVE="$PREFIX-live"

echo "owner: $OWNER    prefix: $PREFIX"
echo

rm -rf "$WORK"
mkdir -p "$WORK"

# --- synthetic values ------------------------------------------------------
# Split from their prefixes so THIS FILE can itself be pushed to GitHub: push
# protection scans every commit of the WhiteHat repository too, and a whole
# SendGrid-shaped string sitting in a committed script is rejected with a
# message that reads nothing like a fixture problem.
SENTRY="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
DANGLING_DETECTOR="SentryToken"
LIVE_DETECTOR="PrivateKey"

# AWS's own documentation example pair. Kept as a negative control: the AWS
# detector checksum-validates the key id and this one fails that check, so a
# clean fixture stays clean even though it is full of credential-shaped strings.
read -r -d '' NEGATIVE_CONTROL <<'EOF' || true
# Negative control. AWS's published documentation example pair, which TruffleHog
# does NOT flag because the detector checksum-validates the key id.
aws:
  access_key_id: AKIAIOSFODNN7EXAMPLE
  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  region: eu-south-1
EOF

# --- verify the values fire before anything is pushed ----------------------
# The shared rule: never build a matrix on a value that was never confirmed to
# trip its detector. A silent non-firing value would read as "the scan missed
# it", which is the exact bug this whole suite exists to catch.
probe_detectors() {
  local probe="$ROOT/_local/ghx_probe"
  rm -rf "$probe"; mkdir -p "$probe"
  printf 'sentry_token=%s\n' "$SENTRY" > "$probe/a.env"
  openssl genrsa -out "$probe/b.pem" 2048 2>/dev/null
  # openssl writes 0600, which the scan container's non-root uid cannot read.
  chmod 644 "$probe/b.pem"
  printf '%s\n' "$NEGATIVE_CONTROL" > "$probe/c.yml"
  docker run --rm -v "$probe:/probe:ro" --entrypoint trufflehog "$TH_IMAGE" \
    filesystem /probe --no-update --json --no-verification 2>/dev/null \
    | jq -r 'select(.DetectorName != null) | .DetectorName' | sort -u
}

echo "[probe] confirming the synthetic values fire against $TH_IMAGE"
FIRED="$(probe_detectors || true)"
echo "$FIRED" | sed 's/^/  detector: /'
for want in "$DANGLING_DETECTOR" "$LIVE_DETECTOR"; do
  if ! grep -qx "$want" <<< "$FIRED"; then
    echo "  ! $want did NOT fire - the fixture would prove nothing. Aborting." >&2
    exit 3
  fi
done
if grep -qx "AWS" <<< "$FIRED"; then
  echo "  ! the negative control FIRED; it is no longer a negative control" >&2
  exit 3
fi
echo "  ok: both values fire, the negative control stays silent"
echo

# --- helpers ---------------------------------------------------------------

repo_exists() { [[ "$(api_code GET "/repos/$OWNER/$1")" == "200" ]]; }

# A fabricated key has an invalid checksum so GitHub's own scanner usually lets
# it through, but push protection is on by default for public repositories and a
# pattern-only match rejects the push. Best effort: a plan without the setting
# answers 422, which is not fatal.
relax_push_protection() {
  api_code PATCH "/repos/$OWNER/$1" \
    '{"security_and_analysis":{"secret_scanning_push_protection":{"status":"disabled"}}}' \
    > /dev/null || true
}

git_init() {
  mkdir -p "$1"
  git -C "$1" init -q -b main
  git -C "$1" config user.email fixture@local
  git -C "$1" config user.name fixture
}

commit() { git -C "$1" add -A && git -C "$1" commit -q -m "$2"; }

# The credential rides in the remote URL for exactly one command and is never
# written into the repository's config.
push_repo() {
  git -C "$WORK/$1" push -q ${3:-} \
    "https://x-access-token:$TOKEN@github.com/$OWNER/$1.git" "${2:-main}"
}

# Returns 0 when it created the repo, 1 when one was already there.
ensure_repo() {
  local name="$1" private="$2"
  if repo_exists "$name"; then
    echo "  = $OWNER/$name exists, left untouched"
    return 1
  fi
  api POST /user/repos "$(jq -nc --arg n "$name" --argjson p "$private" \
    '{name:$n, private:$p, has_wiki:false, has_issues:false, auto_init:false,
      description:"WhiteHat Secret Multiscanner test fixture. Synthetic secrets only."}')" \
    | jq -r '"  + created " + (.full_name // .message)'
  relax_push_protection "$name"
  return 0
}

sha_resolves() { [[ "$(api_code GET "/repos/$OWNER/$DANGLING/commits/$1")" == "200" ]]; }

# --- the dangling repo -----------------------------------------------------
# The live tree is deliberately clean of anything a detector fires on. The ONLY
# secret in this repository lives in a commit that no ref points at.

echo "[dangling] $OWNER/$DANGLING (public)"
D="$WORK/$DANGLING"
if ensure_repo "$DANGLING" false; then
  git_init "$D"
  cat > "$D/README.md" <<EOF
# $DANGLING

WhiteHat Secret Multiscanner fixture for the \`github_experimental\` source.

This repository's live tree contains NO credential any detector fires on, on
purpose. A synthetic Sentry token exists only in a commit that was force-pushed
out of \`main\` and is unreachable from any ref - which is exactly what
\`--object-discovery\` is for. Scanning this repo with the ordinary \`github\`
source must find nothing.
EOF
  printf '%s\n' "$NEGATIVE_CONTROL" > "$D/config.yml"
  commit "$D" "initial commit"
  push_repo "$DANGLING"
  echo "  + pushed a clean main"
else
  git clone -q "https://x-access-token:$TOKEN@github.com/$OWNER/$DANGLING.git" "$D"
  git -C "$D" config user.email fixture@local
  git -C "$D" config user.name fixture
fi

# Reuse the recorded dangling commit when GitHub can still resolve it. GitHub
# does eventually garbage-collect unreachable objects, and a matrix that started
# failing weeks later with no code change is almost always this - so the check
# is explicit and its failure message says so.
PREV_SHA="$(jq -r '.danglingSha // empty' "$MANIFEST" 2>/dev/null || true)"
DANGLING_SHA=""
if [[ -n "$PREV_SHA" ]] && sha_resolves "$PREV_SHA"; then
  DANGLING_SHA="$PREV_SHA"
  echo "  = dangling commit $PREV_SHA still resolves, reused"
else
  if [[ -n "$PREV_SHA" ]]; then
    echo "  ! recorded dangling commit $PREV_SHA no longer resolves"
    echo "    (GitHub garbage-collects unreachable objects); minting a new one"
  fi
  # Guard: only ever force-push a branch inside our own fixture namespace.
  case "$DANGLING" in
    "$PREFIX"-*) ;;
    *) echo "  ! refusing to force-push outside the $PREFIX namespace" >&2; exit 3 ;;
  esac
  BASE="$(git -C "$D" rev-parse HEAD)"
  printf 'sentry_token=%s\n' "$SENTRY" > "$D/leaked.env"
  commit "$D" "oops: add the error-reporting token"
  DANGLING_SHA="$(git -C "$D" rev-parse HEAD)"
  push_repo "$DANGLING"
  # Put the branch back exactly where it was. The object stays on GitHub's
  # servers, resolvable by SHA, reachable from nothing.
  git -C "$D" reset -q --hard "$BASE"
  push_repo "$DANGLING" main --force
  echo "  + minted dangling commit $DANGLING_SHA and force-pushed it out of main"
fi

# Sanity-check the whole premise before a matrix is built on it.
if sha_resolves "$DANGLING_SHA"; then
  echo "  ok: $DANGLING_SHA resolves by SHA"
else
  echo "  ! $DANGLING_SHA does NOT resolve - the fixture is not usable" >&2
  exit 3
fi
if git -C "$D" cat-file -e "$DANGLING_SHA^{commit}" 2>/dev/null \
   && git -C "$D" merge-base --is-ancestor "$DANGLING_SHA" HEAD 2>/dev/null; then
  echo "  ! $DANGLING_SHA is still reachable from main - it is not dangling" >&2
  exit 3
fi
echo "  ok: unreachable from main"

# --- the live repo ---------------------------------------------------------
# The control: an ordinary secret in the working tree and no dangling objects at
# all, so case 3 can say what object discovery does when there is nothing hidden.

echo "[live] $OWNER/$LIVE (public)"
if ensure_repo "$LIVE" false; then
  D="$WORK/$LIVE"
  git_init "$D"
  cat > "$D/README.md" <<EOF
# $LIVE

WhiteHat Secret Multiscanner fixture. A synthetic RSA deploy key sits in the LIVE
tree and nothing has ever been force-pushed here, so \`--object-discovery\` has
no hidden object to find.
EOF
  openssl genrsa -out "$D/deploy_key.pem" 2048 2>/dev/null
  chmod 644 "$D/deploy_key.pem"
  printf '%s\n' "$NEGATIVE_CONTROL" > "$D/config.yml"
  commit "$D" "add synthetic deploy key"
  push_repo "$LIVE"
  echo "  + pushed"
fi

# --- manifest --------------------------------------------------------------
# Flat keys, read by the matrix, the graph check and the Playwright spec. The
# account login lives HERE and never in a committed file.

jq -nc \
  --arg owner "$OWNER" --arg prefix "$PREFIX" \
  --arg dangling "$OWNER/$DANGLING" --arg live "$OWNER/$LIVE" \
  --arg sha "$DANGLING_SHA" \
  --arg dd "$DANGLING_DETECTOR" --arg ld "$LIVE_DETECTOR" \
  '{owner:$owner, prefix:$prefix, dangling:$dangling, live:$live,
    danglingSha:$sha, danglingDetector:$dd, liveDetector:$ld}' \
  > "$MANIFEST"

echo
echo "manifest: $MANIFEST"
jq . "$MANIFEST"
rm -rf "$WORK" "$ROOT/_local/ghx_probe"
