#!/usr/bin/env bash
# Build the GitHub fixtures the `github` source matrix measures against.
#
# SYNTHETIC credentials only. Every value below is fabricated, and each was
# verified to FIRE its detector against the pinned TruffleHog 3.96.0 binary.
# None is, or ever was, a real credential. Verification against the owning API
# is expected to come back dead - that is itself one of the matrix's cases.
#
# CREATE-ONLY. This script never deletes anything, and has no destroy mode on
# purpose: the token is not expected to carry `delete_repo`, and a fixture
# builder that can delete repositories is one typo away from removing real work.
# A repository that already exists is left exactly as it is. Clean up by hand.
#
# One detector per LOCATION, deliberately. Every fixture site carries a detector
# that appears nowhere else, so "did --include-wikis actually reach the wiki" is
# a question about one detector name rather than a count that could be explained
# three ways:
#
#   alpha  .env.example    Github, SlackWebhook     delta         (no secrets)
#   alpha  deploy_key.pem  PrivateKey               delta  wiki   NpmToken
#   alpha  issue comment   SendGrid                 beta          DatadogApikey
#   alpha  PR body+comment Mailgun                  gamma         Shippo
#   gist   notes.md        LinearAPI                gist comment  SentryToken
#
# Visibility is not cosmetic:
#   alpha/beta/gamma are PRIVATE - a finding in one proves the token was really
#     injected, since an anonymous scan cannot see them at all.
#   delta is PUBLIC - GitHub only offers wikis on private repos to paid plans,
#     so the wiki fixture cannot live on a private repo.
#
# Usage:  testing/e2e/backend/build_github_fixtures.sh
# Token:  _local/gh_fixture_token, or $GITHUB_FIXTURE_TOKEN. Needs `repo`+`gist`.
# Writes: _local/github_fixtures.json, the manifest both harnesses read.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORK="$ROOT/_local/gh_fixture_build"
MANIFEST="$ROOT/_local/github_fixtures.json"
PREFIX="${WHITEHAT_FIXTURE_PREFIX:-whitehat-th}"
UPSTREAM_FORK="trufflesecurity/test_keys"

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
echo "owner: $OWNER    prefix: $PREFIX"
echo

ALPHA="$PREFIX-alpha"
BETA="$PREFIX-beta"
GAMMA="$PREFIX-gamma"
DELTA="$PREFIX-delta"
FORK="${UPSTREAM_FORK##*/}"

rm -rf "$WORK"
mkdir -p "$WORK"

# --- helpers ---------------------------------------------------------------

repo_exists() { [[ "$(api_code GET "/repos/$OWNER/$1")" == "200" ]]; }

# A fabricated ghp_ value has an invalid checksum so GitHub's own scanner
# usually lets it through, but push protection is on by default for public
# repos and a pattern-only match would reject the push with a message that
# reads nothing like a fixture problem. Best-effort: a plan without the setting
# answers 422, which is not fatal.
relax_push_protection() {
  api_code PATCH "/repos/$OWNER/$1" \
    '{"security_and_analysis":{"secret_scanning_push_protection":{"status":"disabled"}}}' \
    > /dev/null || true
}

# Returns 0 when it created the repo, 1 when one was already there.
ensure_repo() {
  local name="$1" private="$2" wiki="${3:-false}"
  if repo_exists "$name"; then
    echo "  = $OWNER/$name exists, left untouched"
    return 1
  fi
  api POST /user/repos "$(jq -nc \
    --arg n "$name" --argjson p "$private" --argjson w "$wiki" \
    '{name:$n, private:$p, has_wiki:$w, has_issues:true, auto_init:false,
      description:"WhiteHat Secret Multiscanner test fixture. Synthetic secrets only."}')" \
    | jq -r '"  + created " + (.full_name // .message)'
  relax_push_protection "$name"
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
# written into the repository's config.
push_repo() {
  git -C "$WORK/$1" push -q \
    "https://x-access-token:$TOKEN@github.com/$OWNER/$1.git" "${2:-main}"
}

# --- alpha: the private baseline ------------------------------------------
# Two commits so history-depth options have something to bite on, and the two
# secret-bearing files kept apart so the path filters can select one.

echo "[alpha] $OWNER/$ALPHA (private)"
if ensure_repo "$ALPHA" true; then
  D="$WORK/$ALPHA"
  git_init "$D"
  cat > "$D/README.md" <<'EOF'
# whitehat-th-alpha

WhiteHat Secret Multiscanner fixture. Every credential-shaped string here is
fabricated and has never been valid anywhere.
EOF
  # Split from its tail because GitHub's push protection rejects a commit
  # carrying a whole webhook, fabricated or not. The fixture repo still gets it.
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
  openssl genrsa -out "$D/deploy_key.pem" 2048 2>/dev/null
  # openssl writes 0600, which the scan container's non-root uid cannot read;
  # git records the mode, so it has to be relaxed before the commit.
  chmod 644 "$D/deploy_key.pem"
  commit "$D" "add synthetic credentials for scanner testing"
  sed -i 's/eu-south-1/eu-west-1/' "$D/config.yml"
  commit "$D" "move the example region (history keeps the first commit)"
  push_repo "$ALPHA"
  echo "  + pushed 2 commits"
fi

# --- beta: private, proves the token is really being used -----------------

echo "[beta] $OWNER/$BETA (private)"
if ensure_repo "$BETA" true; then
  D="$WORK/$BETA"
  git_init "$D"
  printf '# whitehat-th-beta\n\nA finding here proves the GitHub token was injected.\n' > "$D/README.md"
  # `datadog_api_key=`, NOT `dd_api_key=`: TruffleHog prefilters candidate
  # chunks by detector KEYWORD before the pattern runs, and the Datadog
  # detector's keyword is "datadog". The abbreviated spelling this used to carry
  # is never considered, so beta yielded NO findings at all and every case
  # asserting that beta contributed one was measuring something else. Only
  # affects freshly built fixtures: an existing beta is left untouched, so
  # rewrite monitoring.env by hand to repair one that was already created.
  printf 'datadog_api_key=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n' > "$D/monitoring.env"
  commit "$D" "add synthetic monitoring credential"
  push_repo "$BETA"
  echo "  + pushed"
fi

# --- gamma: archived, for --exclude-archived ------------------------------
# Archived LAST: an archived repository is read-only, so the push has to land
# before the flag is set.

echo "[gamma] $OWNER/$GAMMA (private, archived)"
if ensure_repo "$GAMMA" true; then
  D="$WORK/$GAMMA"
  git_init "$D"
  printf '# whitehat-th-gamma\n\nArchived fixture, for the "Exclude archived" toggle.\n' > "$D/README.md"
  # Split for the same push-protection reason as alpha's Slack webhook.
  SHIPPO_TAIL='a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0'
  printf 'SHIPPO_TOKEN=shippo_live_%s\n' "$SHIPPO_TAIL" > "$D/shipping.env"
  commit "$D" "add synthetic shipping credential"
  push_repo "$GAMMA"
  echo "  + pushed"
fi
if [[ "$(api GET "/repos/$OWNER/$GAMMA" | jq -r .archived)" != "true" ]]; then
  api PATCH "/repos/$OWNER/$GAMMA" '{"archived":true}' \
    | jq -r '"  archived: " + ((.archived|tostring) // .message)'
fi

# --- delta: PUBLIC, empty of secrets, host for the wiki fixture -----------
# Public because GitHub does not offer wikis on a private repo below a paid
# plan. Its code is deliberately clean, which is what makes the wiki contrast
# readable: any finding at all in a delta scan came from the wiki.

echo "[delta] $OWNER/$DELTA (public, wiki host)"
if ensure_repo "$DELTA" false true; then
  D="$WORK/$DELTA"
  git_init "$D"
  cat > "$D/README.md" <<'EOF'
# whitehat-th-delta

WhiteHat Secret Multiscanner fixture. This repository's CODE contains no
credentials of any kind, on purpose: its wiki does. That contrast is what the
"Include wikis" test measures.
EOF
  commit "$D" "add readme"
  push_repo "$DELTA"
  echo "  + pushed"
fi
# has_wiki can be off on a repo created before this script set it.
api PATCH "/repos/$OWNER/$DELTA" '{"has_wiki":true}' > /dev/null

# --- fork: for --include-forks -------------------------------------------
# Forked rather than fabricated because a fork must have an upstream. The
# upstream is TruffleHog's own published test corpus, which exists for this.

echo "[fork] $OWNER/$FORK (fork of $UPSTREAM_FORK)"
if repo_exists "$FORK"; then
  echo "  = exists, left untouched"
else
  api POST "/repos/$UPSTREAM_FORK/forks" '{}' | jq -r '"  + " + (.full_name // .message)'
  echo "  (forks are created asynchronously; give it a few seconds)"
fi

# --- wiki on delta: for --include-wikis ----------------------------------
# A wiki is its own git repository at <repo>.wiki.git, and GitHub has NO REST
# endpoint that creates its first page. Until one page exists, the wiki repo
# does not exist either and a push is answered "Repository not found" - so this
# step is the one part of the fixture set that needs a human, once.

echo "[wiki] $OWNER/$DELTA.wiki"
D="$WORK/${DELTA}.wiki"
git_init "$D"
cat > "$D/Home.md" <<'EOF'
# Deployment notes

Internal registry access for the build agents:

    NPM_TOKEN=npm_iEDPP1TudBqvzVpBrIcHFJDVbrGwiC0dbfmL

Synthetic. Never valid anywhere.
EOF
commit "$D" "add deployment notes"
WIKI_READY=false
if git -C "$D" push -q \
    "https://x-access-token:$TOKEN@github.com/$OWNER/$DELTA.wiki.git" main 2>"$WORK/wiki.err"; then
  echo "  + pushed Home.md"
  WIKI_READY=true
else
  echo "  ! wiki not initialised yet - the two --include-wikis cases will be skipped."
  echo "    ONE-TIME manual step (GitHub has no API for it):"
  echo "      open https://github.com/$OWNER/$DELTA/wiki"
  echo "      click 'Create the first page', save anything, then re-run this script."
fi

# --- issue + comment on alpha: for --issue-comments ----------------------

echo "[issue] $OWNER/$ALPHA"
ISSUE="$(api GET "/repos/$OWNER/$ALPHA/issues?state=all&per_page=100" \
  | jq -r '[.[] | select(.pull_request == null)] | sort_by(.number) | .[0].number // empty')"
if [[ -z "$ISSUE" ]]; then
  ISSUE="$(api POST "/repos/$OWNER/$ALPHA/issues" "$(jq -nc \
    '{title:"Fixture: leaked key in a comment",
      body:"Tracking the staging key rotation. The old value is in the comment below."}')" \
    | jq -r '.number // empty')"
  echo "  + issue #$ISSUE"
fi
if [[ -n "$ISSUE" ]]; then
  if api GET "/repos/$OWNER/$ALPHA/issues/$ISSUE/comments" | grep -q 'SG\.'; then
    echo "  = comment already present"
  else
    api POST "/repos/$OWNER/$ALPHA/issues/$ISSUE/comments" "$(jq -nc \
      '{body:"Old staging mailer key, now retired:\n\n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\n"}')" \
      > /dev/null
    echo "  + comment carrying the SendGrid value"
  fi
fi

# --- PR + comment on alpha: for --pr-comments ----------------------------
# The PR BRANCH carries no secret on purpose. A secret in the diff would be
# found by the ordinary repo scan (every ref is scanned), and then "the PR
# comment was read" and "the branch was cloned" would be indistinguishable.

echo "[pr] $OWNER/$ALPHA"
PR="$(api GET "/repos/$OWNER/$ALPHA/pulls?state=all&per_page=100" \
  | jq -r 'sort_by(.number) | .[0].number // empty')"
if [[ -z "$PR" ]]; then
  D="$WORK/$ALPHA"
  if [[ ! -d "$D" ]]; then
    git clone -q "https://x-access-token:$TOKEN@github.com/$OWNER/$ALPHA.git" "$D"
    git -C "$D" config user.email fixture@local
    git -C "$D" config user.name fixture
  fi
  git -C "$D" checkout -q -B chore/docs
  printf '\n## Rotation\n\nSee the open issue.\n' >> "$D/README.md"
  commit "$D" "document the rotation"
  push_repo "$ALPHA" chore/docs
  PR="$(api POST "/repos/$OWNER/$ALPHA/pulls" "$(jq -nc \
    '{title:"Fixture: leaked key in a PR body", head:"chore/docs", base:"main",
      body:"Docs only. For reference, the mailer key being retired was key-3ax6xnjp29jd6fds4gc373sgvjxteol0\n"}')" \
    | jq -r '.number // empty')"
  echo "  + PR #$PR (secret in the description, not in the diff)"
fi
if [[ -n "$PR" ]]; then
  if api GET "/repos/$OWNER/$ALPHA/issues/$PR/comments" | grep -q 'key-3ax6'; then
    echo "  = comment already present"
  else
    api POST "/repos/$OWNER/$ALPHA/issues/$PR/comments" "$(jq -nc \
      '{body:"Confirming the retired value: key-3ax6xnjp29jd6fds4gc373sgvjxteol0\n"}')" > /dev/null
    echo "  + comment carrying the Mailgun value"
  fi
fi

# --- gist + comment: for --ignore-gists and --gist-comments --------------
# Gists belong to a USER, never an organization, so these two toggles can only
# be exercised by pointing the scan at an account login.

echo "[gist] $OWNER"
GIST="$(api GET "/gists?per_page=100" \
  | jq -r '[.[] | select(.description | startswith("WhiteHat"))]
           | sort_by(.created_at) | .[0].id // empty')"
if [[ -z "$GIST" ]]; then
  GIST="$(api POST /gists "$(jq -nc \
    '{description:"WhiteHat Secret Multiscanner fixture", public:true,
      files:{"notes.md":{content:"Issue tracker integration key (synthetic):\n\nlin_api_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0\n"}}}')" \
    | jq -r '.id // empty')"
  echo "  + gist $GIST"
fi
if [[ -n "$GIST" ]]; then
  if api GET "/gists/$GIST/comments" | grep -q 'sentry'; then
    echo "  = gist comment already present"
  else
    api POST "/gists/$GIST/comments" "$(jq -nc \
      '{body:"Related, also retired: sentry_token=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2\n"}')" \
      > /dev/null
    echo "  + gist comment carrying the SentryToken value"
  fi
fi

# --- manifest -------------------------------------------------------------
# Flat keys: the Playwright spec reads them directly, the Python matrix derives
# every repository name from owner+prefix and needs only the gist id.

jq -nc \
  --arg owner "$OWNER" --arg prefix "$PREFIX" \
  --arg alpha "$OWNER/$ALPHA" --arg beta "$OWNER/$BETA" \
  --arg gamma "$OWNER/$GAMMA" --arg delta "$OWNER/$DELTA" \
  --arg fork "$OWNER/$FORK" \
  --arg issue "${ISSUE:-}" --arg pr "${PR:-}" --arg gist "${GIST:-}" \
  --argjson wiki "$WIKI_READY" \
  '{owner:$owner, prefix:$prefix, alpha:$alpha, beta:$beta, gamma:$gamma,
    delta:$delta, fork:$fork, issue:$issue, pr:$pr, gist:$gist,
    wikiReady:$wiki}' \
  > "$MANIFEST"

echo
echo "manifest: $MANIFEST"
jq . "$MANIFEST"
rm -rf "$WORK"
