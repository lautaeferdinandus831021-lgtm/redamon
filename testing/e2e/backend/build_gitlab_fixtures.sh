#!/usr/bin/env bash
# Build the GitLab fixtures the `gitlab` source matrix measures against.
#
# SYNTHETIC credentials only. Every value below is fabricated, and each was
# verified to FIRE its detector against the pinned TruffleHog 3.96.0 binary.
# None is, or ever was, a real credential. Verification against the owning API
# is expected to come back dead - that is itself one of the matrix's cases.
#
# CREATE-ONLY. This script never deletes anything, and has no destroy mode on
# purpose: a fixture builder that can delete projects is one typo away from
# removing real work. A project that already exists is left exactly as it is.
# Clean up by hand.
#
# One detector per LOCATION, deliberately. Every fixture site carries a detector
# that appears nowhere else, so "did --include-paths actually reach the pem" is
# a question about one detector name rather than a count that could be explained
# three ways:
#
#   alpha  .env.example        Github, SlackWebhook   beta   monitoring.env  DatadogApikey
#   alpha  keys/deploy_key.pem PrivateKey             gamma  shipping.env    Shippo
#   alpha  config.yml          (none - negative control)
#
# Visibility is not cosmetic:
#   alpha/beta are PRIVATE - a finding in one proves the token was really
#     injected, since an anonymous scan cannot see them at all.
#   gamma is PUBLIC, which forces the GROUP to be public too: GitLab refuses a
#     project whose visibility is more permissive than its namespace's. The
#     group name is therefore world-visible; the private projects inside it are
#     not. A brand-new free account that may not create a public namespace falls
#     back to private for both, recorded as `gammaVisibility` in the manifest.
#
# Names are chosen so a glob bites exactly one project: `<group>/a*` selects
# alpha alone. alpha gets TWO commits so history has depth, and its two
# secret-bearing files sit in different paths so --include-paths /
# --exclude-paths can select one.
#
# Usage:  testing/e2e/backend/build_gitlab_fixtures.sh
# Token:  _local/gitlab_fixture_token, or $GITLAB_FIXTURE_TOKEN.
#         Scopes: `api` (to create the group and the projects) + `write_repository`
#         for the pushes. A read-only token cannot build these fixtures; the
#         MATRIX only needs read_api + read_repository.
# Writes: _local/gitlab_fixtures.json, the manifest all three harnesses read.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORK="$ROOT/_local/gitlab_fixture_build"
MANIFEST="$ROOT/_local/gitlab_fixtures.json"
HOST="${GITLAB_HOST:-https://gitlab.com}"
GROUP_PATH="${WHITEHAT_FIXTURE_GROUP:-whitehat-th-group}"

TOKEN="${GITLAB_FIXTURE_TOKEN:-}"
if [[ -z "$TOKEN" && -f "$ROOT/_local/gitlab_fixture_token" ]]; then
  TOKEN="$(tr -d '[:space:]' < "$ROOT/_local/gitlab_fixture_token")"
fi
if [[ -z "$TOKEN" ]]; then
  echo "no token: set GITLAB_FIXTURE_TOKEN or write _local/gitlab_fixture_token" >&2
  exit 2
fi

API="$HOST/api/v4"

# `set -e` plus a failing curl inside a command substitution would abort with no
# context, so every call reports its own body and the caller decides.
api() {
  local method="$1" path="$2" body="${3:-}"
  local -a args=(-sS -X "$method" -H "PRIVATE-TOKEN: $TOKEN")
  [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" -d "$body")
  curl "${args[@]}" "$API$path"
}

api_code() {
  local method="$1" path="$2" body="${3:-}"
  local -a args=(-sS -o /dev/null -w '%{http_code}' -X "$method"
    -H "PRIVATE-TOKEN: $TOKEN")
  [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" -d "$body")
  curl "${args[@]}" "$API$path"
}

# `jq -sRr @uri` rather than a hand-rolled sed: a group path with a slash in it
# (a subgroup) must arrive percent-encoded or the API reads it as another route.
urlenc() { printf '%s' "$1" | jq -sRr @uri; }

# NOT fatal when empty. A fine-grained token can legitimately be issued without
# read access to the user resource, and the username is only ever used to
# compose a fallback group path and to label the manifest. The token is proved
# to work by the group lookup below instead.
USERNAME="$(api GET /user | jq -r '.username // empty' 2>/dev/null || true)"
echo "host: $HOST    user: ${USERNAME:-<not readable with this token>}"
echo

# --- the group -------------------------------------------------------------
# `owned=true`, not a bare path lookup: on gitlab.com a top-level path is
# globally unique, so GET /groups/<path> would happily return SOMEONE ELSE's
# group and the builder would then try to create projects inside it. Only a
# group this token owns may be reused.

# An explicit parent group, for the new-account case above. Its visibility is a
# ceiling on everything inside it: GitLab refuses a child more visible than its
# parent, so a private parent forces private fixtures.
PARENT_ID=""
if [[ -n "${WHITEHAT_FIXTURE_PARENT:-}" ]]; then
  PARENT_ID="$(api GET "/groups/$(urlenc "$WHITEHAT_FIXTURE_PARENT")" | jq -r '.id // empty')"
  if [[ -z "$PARENT_ID" ]]; then
    echo "parent group '$WHITEHAT_FIXTURE_PARENT' not found or not readable" >&2
    exit 2
  fi
  GROUP_PATH="$WHITEHAT_FIXTURE_PARENT/${GROUP_PATH##*/}"
fi

echo "[group] $GROUP_PATH"

# Searched by the LAST path segment, then matched on the FULL path. GitLab's
# group search does not match a value containing a slash, so searching for
# `parent/child` verbatim returns nothing and a subgroup would look absent and
# be re-created on every run. `owned=true` is what keeps this to groups this
# token owns: on gitlab.com a top-level path is globally unique, so a bare
# `GET /groups/<path>` would happily return SOMEONE ELSE's group.
find_owned_group() {
  api GET "/groups?owned=true&search=$(urlenc "${1##*/}")&per_page=100" \
    | jq -r --arg p "$1" '[.[] | select(.full_path == $p)] | .[0].id // empty'
}

# Try the preferred path, then a per-account one. On gitlab.com a top-level
# group path is GLOBALLY unique, so `whitehat-th-group` is very likely already
# taken by someone else - and a bare `GET /groups/<path>` would return THEIR
# group happily. `owned=true` is what keeps this to groups this token owns.
GROUP_ID="$(find_owned_group "$GROUP_PATH")"
if [[ -z "$GROUP_ID" && -z "${WHITEHAT_FIXTURE_GROUP:-}" && -n "$USERNAME" ]]; then
  ALT="whitehat-th-$USERNAME"
  ALT_ID="$(find_owned_group "$ALT")"
  if [[ -n "$ALT_ID" ]]; then
    GROUP_PATH="$ALT"; GROUP_ID="$ALT_ID"
  fi
fi

# Public, because gamma is public: GitLab refuses a project more visible than
# its namespace, so a private group could not hold a public project at all. A
# brand-new free account is sometimes barred from creating public namespaces
# until identity verification, so this falls back to private rather than dying -
# and records the outcome in the manifest, because it decides whether the
# "public project" half of the fixture set exists at all.
GROUP_VISIBILITY=public

# gitlab.com refuses a TOP-LEVEL group to a new free account with a bare
# "403 Forbidden" and no explanation, while a SUBGROUP under a group the account
# already owns is allowed. WHITEHAT_FIXTURE_PARENT names that parent; with it set,
# GROUP_PATH is the child path and the fixtures land at <parent>/<child>.
create_group() {
  local path="${1##*/}"
  local parent_arg='{}'
  if [[ -n "${PARENT_ID:-}" ]]; then
    parent_arg="$(jq -nc --argjson id "$PARENT_ID" '{parent_id:$id}')"
  fi
  api POST /groups "$(jq -nc --arg p "$path" --arg v "$2" --argjson extra "$parent_arg" \
    '{name:$p, path:$p, visibility:$v,
      description:"WhiteHat Secret Multiscanner test fixtures. Synthetic secrets only."}
     + $extra')"
}

if [[ -z "$GROUP_ID" ]]; then
  CREATED="$(create_group "$GROUP_PATH" public)"
  GROUP_ID="$(jq -r '.id // empty' <<<"$CREATED")"

  if [[ -z "$GROUP_ID" ]] && grep -qi 'visibility' <<<"$CREATED"; then
    echo "  ! public group refused ($(jq -rc '.message // .error' <<<"$CREATED")); retrying private"
    CREATED="$(create_group "$GROUP_PATH" private)"
    GROUP_ID="$(jq -r '.id // empty' <<<"$CREATED")"
    [[ -n "$GROUP_ID" ]] && GROUP_VISIBILITY=private
  fi

  # "has already been taken" is the globally-unique-path collision.
  if [[ -z "$GROUP_ID" && -z "${WHITEHAT_FIXTURE_GROUP:-}" && -n "$USERNAME" ]]; then
    echo "  ! '$GROUP_PATH' unavailable ($(jq -rc '.message // .error' <<<"$CREATED"))"
    GROUP_PATH="whitehat-th-$USERNAME"
    echo "  > retrying as '$GROUP_PATH'"
    CREATED="$(create_group "$GROUP_PATH" public)"
    GROUP_ID="$(jq -r '.id // empty' <<<"$CREATED")"
    if [[ -z "$GROUP_ID" ]]; then
      CREATED="$(create_group "$GROUP_PATH" private)"
      GROUP_ID="$(jq -r '.id // empty' <<<"$CREATED")"
      [[ -n "$GROUP_ID" ]] && GROUP_VISIBILITY=private
    fi
  fi

  if [[ -z "$GROUP_ID" ]]; then
    echo "  ! could not create a group: $(jq -rc '.message // .error // .' <<<"$CREATED")" >&2
    echo "    Two fixes, either works:" >&2
    echo "      - the path is taken: pick another with WHITEHAT_FIXTURE_GROUP=<path>" >&2
    echo "      - the token may not create groups (a fine-grained token has no" >&2
    echo "        global group-create permission): create the group by hand at" >&2
    echo "        $HOST/groups/new, then re-run with WHITEHAT_FIXTURE_GROUP=<its path>" >&2
    exit 2
  fi
  echo "  + created group '$GROUP_PATH' id=$GROUP_ID visibility=$GROUP_VISIBILITY"
else
  GROUP_VISIBILITY="$(api GET "/groups/$GROUP_ID" | jq -r '.visibility // "private"')"
  echo "  = group '$GROUP_PATH' id=$GROUP_ID exists and is owned by this token, left untouched"
fi

# gamma can only be public inside a public namespace.
GAMMA_VISIBILITY=public
if [[ "$GROUP_VISIBILITY" != "public" ]]; then
  GAMMA_VISIBILITY=private
  echo "  ! the group is $GROUP_VISIBILITY, so gamma will be private too"
fi

rm -rf "$WORK"
mkdir -p "$WORK"

# --- helpers ---------------------------------------------------------------

project_exists() {
  [[ "$(api_code GET "/projects/$(urlenc "$GROUP_PATH/$1")")" == "200" ]]
}

project_is_empty() {
  [[ "$(api GET "/projects/$(urlenc "$GROUP_PATH/$1")" | jq -r '.empty_repo // false')" == "true" ]]
}

# Returns 0 when the caller should build and push content, 1 when a POPULATED
# project is already there and must be left alone.
#
# An EMPTY existing project counts as "build it": creating the project and
# pushing to it are two steps, and the push is the one that fails (GitLab needs a
# moment before a new project accepts one). Treating exists-and-empty as done
# would leave a partial run permanently broken, with the builder cheerfully
# reporting "left untouched" on every retry. Still create-only: nothing is ever
# deleted, and a project with commits in it is never touched.
ensure_project() {
  local name="$1" visibility="$2"
  if project_exists "$name"; then
    if project_is_empty "$name"; then
      echo "  ~ $GROUP_PATH/$name exists but is EMPTY, pushing its content"
      return 0
    fi
    echo "  = $GROUP_PATH/$name exists with commits, left untouched"
    return 1
  fi
  api POST /projects "$(jq -nc \
    --arg n "$name" --arg v "$visibility" --argjson g "$GROUP_ID" \
    '{name:$n, path:$n, namespace_id:$g, visibility:$v,
      initialize_with_readme:false,
      description:"WhiteHat Secret Multiscanner test fixture. Synthetic secrets only."}')" \
    | jq -r '"  + created " + (.path_with_namespace // (.message | tostring))'
  return 0
}

git_init() {
  mkdir -p "$1"
  git -C "$1" init -q -b main
  git -C "$1" config user.email fixture@local
  git -C "$1" config user.name fixture
}

commit() { git -C "$1" add -A && git -C "$1" commit -q -m "$2"; }

# The credential rides in the remote URL for exactly one command and is never
# written into the repository's config. `oauth2:<token>` is the form GitLab
# documents for a personal access token over https.
# Retried, because a project is not pushable the instant POST /projects returns:
# GitLab answers the first push with "The project you were looking for could not
# be found or you don't have permission to view it", which reads exactly like a
# bad token and is in fact a propagation delay of a second or two.
push_project() {
  local host_noscheme="${HOST#https://}"
  host_noscheme="${host_noscheme#http://}"
  local url="https://oauth2:$TOKEN@$host_noscheme/$GROUP_PATH/$1.git"
  local attempt
  for attempt in 1 2 3 4 5; do
    if git -C "$WORK/$1" push -q "$url" "${2:-main}" 2>"$WORK/push.err"; then
      return 0
    fi
    sleep $(( attempt * 2 ))
  done
  echo "  ! push failed after 5 attempts: $(tr -d '\r' < "$WORK/push.err" | tail -2)" >&2
  return 1
}

ALPHA=alpha
BETA=beta
GAMMA=gamma

# --- alpha: the private baseline ------------------------------------------

echo "[alpha] $GROUP_PATH/$ALPHA (private)"
if ensure_project "$ALPHA" private; then
  D="$WORK/$ALPHA"
  git_init "$D"
  cat > "$D/README.md" <<'EOF'
# alpha

WhiteHat Secret Multiscanner fixture. Every credential-shaped string here is
fabricated and has never been valid anywhere.
EOF
  # Split from its tail so no whole webhook literal sits in this builder; the
  # fixture repository still receives the complete value.
  SLACK_TAIL='XXXXXXXXXXXXXXXXXXXXXXXX'
  cat > "$D/.env.example" <<EOF
GITHUB_TOKEN=ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8
SLACK_WEBHOOK=https://hooks.slack.com/services/T00000000/B00000000/$SLACK_TAIL
EOF
  # AWS's own published example pair, kept as a NEGATIVE control: TruffleHog
  # does not flag it, because the AWS detector checksum-validates the key id and
  # this documentation example fails that check. A fixture set with no negative
  # control cannot tell "the scan worked" from "the scan flags everything".
  cat > "$D/config.yml" <<'EOF'
aws:
  access_key_id: AKIAIOSFODNN7EXAMPLE
  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  region: eu-south-1
EOF
  # A DIFFERENT directory from .env.example on purpose: --include-paths and
  # --exclude-paths are only meaningfully proven when the two secret-bearing
  # files can be told apart by their path alone.
  mkdir -p "$D/keys"
  openssl genrsa -out "$D/keys/deploy_key.pem" 2048 2>/dev/null
  # openssl writes 0600, which the scan container's non-root uid cannot read;
  # git records the mode, so it has to be relaxed before the commit or
  # PrivateKey silently never fires.
  chmod 644 "$D/keys/deploy_key.pem"
  commit "$D" "add synthetic credentials for scanner testing"
  sed -i 's/eu-south-1/eu-west-1/' "$D/config.yml"
  commit "$D" "move the example region (history keeps the first commit)"
  push_project "$ALPHA"
  echo "  + pushed 2 commits"
fi

# --- beta: private, proves the token is really being used -----------------

echo "[beta] $GROUP_PATH/$BETA (private)"
if ensure_project "$BETA" private; then
  D="$WORK/$BETA"
  git_init "$D"
  printf '# beta\n\nA finding here proves the GitLab token was injected.\n' > "$D/README.md"
  # `datadog_api_key=`, NOT `dd_api_key=`: TruffleHog prefilters candidate
  # chunks by detector KEYWORD before the pattern ever runs, and the Datadog
  # detector's keyword is "datadog". With the abbreviated name the value is
  # never even considered, and the repository silently yields nothing - verified
  # against the pinned 3.96.0 binary by scanning both spellings locally.
  printf 'datadog_api_key=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n' > "$D/monitoring.env"
  commit "$D" "add synthetic monitoring credential"
  push_project "$BETA"
  echo "  + pushed"
fi

# --- gamma: public --------------------------------------------------------

echo "[gamma] $GROUP_PATH/$GAMMA ($GAMMA_VISIBILITY)"
if ensure_project "$GAMMA" "$GAMMA_VISIBILITY"; then
  D="$WORK/$GAMMA"
  git_init "$D"
  printf '# gamma\n\nPublic fixture, for the exclude/include glob cases.\n' > "$D/README.md"
  SHIPPO_TAIL='a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0'
  printf 'SHIPPO_TOKEN=shippo_live_%s\n' "$SHIPPO_TAIL" > "$D/shipping.env"
  commit "$D" "add synthetic shipping credential"
  push_project "$GAMMA"
  echo "  + pushed"
fi

# --- manifest -------------------------------------------------------------
# The full https URL is what the `repos` field takes: unlike github, the GitLab
# source refuses `group/project` shorthand (it answers "Gitlab requires
# http/https repo urls" at INFO level and then scans nothing for it), which is
# why validate_config rejects the shorthand before a run can silently miss.
#
# `visibleProjects` is how the matrix decides whether the empty-scope case
# (no repos, no group ids - which scans EVERY project the token can reach) is
# safe to run or must be skipped with a printed reason.

VISIBLE="$(api GET "/projects?membership=true&simple=true&per_page=100" | jq 'length')"

jq -nc \
  --arg host "$HOST" --arg group "$GROUP_PATH" --argjson groupId "$GROUP_ID" \
  --arg user "$USERNAME" \
  --arg alpha "$HOST/$GROUP_PATH/$ALPHA.git" \
  --arg beta "$HOST/$GROUP_PATH/$BETA.git" \
  --arg gamma "$HOST/$GROUP_PATH/$GAMMA.git" \
  --arg gammaVisibility "$GAMMA_VISIBILITY" \
  --argjson visible "${VISIBLE:-0}" \
  '{host:$host, group:$group, groupId:$groupId, user:$user,
    alpha:$alpha, beta:$beta, gamma:$gamma,
    alphaPath:($group + "/alpha"), betaPath:($group + "/beta"),
    gammaPath:($group + "/gamma"),
    gammaVisibility:$gammaVisibility,
    visibleProjects:$visible}' \
  > "$MANIFEST"

echo
echo "manifest: $MANIFEST"
jq . "$MANIFEST"
if [[ "${VISIBLE:-0}" -gt 3 ]]; then
  echo
  echo "note: this token can reach $VISIBLE projects, more than the 3 fixtures."
  echo "      The empty-scope matrix case (no repos + no group ids) would scan"
  echo "      all of them, so it will SKIP itself and say so."
fi
rm -rf "$WORK"
