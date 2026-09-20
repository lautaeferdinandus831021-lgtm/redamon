#!/usr/bin/env bash
# =============================================================================
# MCP access tokens — Postgres integration test (L4)
# =============================================================================
# Every mcpAuth unit test mocks Prisma, so they all pass even if the model and
# the queries disagree with the actual database. This asserts at the DATABASE
# level what the token model promises, because the credential's whole security
# story rests on it:
#
#   ROW 4  mint -> resolve -> revoke -> expire round-trips on real Postgres
#   ROW 5  token_hash is UNIQUE; deleting a user cascades their tokens away
#   ROW 6  a password change revokes every live token in ONE transaction, and a
#          failed change revokes none
#   ROW 7  pruning deletes only rows dead longer than the window; NULL
#          revoked_at / expires_at (i.e. LIVE tokens) survive
#
# Row 7 is the one a mocked test cannot catch: `revokedAt: { lt: cutoff }` in
# Prisma becomes `revoked_at < cutoff` in SQL, and in SQL a NULL comparison is
# NULL, not false. Getting that wrong the other way (IS NULL OR <) would delete
# every live token in the system.
#
# Requires the stack's postgres container:  docker compose up -d postgres
# Usage: bash tests/mcp_tokens_db_test.sh
# =============================================================================
set -uo pipefail

cd "$(dirname "$0")/.."

PSQL=(docker compose exec -T postgres psql -U "${POSTGRES_USER:-whitehat}" -d "${POSTGRES_DB:-whitehat}" -qtAX)

pass=0
fail=0
ok()  { echo "  PASS  $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL  $1"; echo "        $2"; fail=$((fail + 1)); }
q()   { "${PSQL[@]}" -c "$1" 2>&1; }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$2' got '$3'"; fi; }

echo "== MCP access tokens: DB integration =="

if ! q "select 1" >/dev/null 2>&1; then
  echo "  SKIP  postgres container not reachable (docker compose up -d postgres)"
  exit 0
fi
if [ "$(q "select to_regclass('public.mcp_access_tokens') is not null")" != "t" ]; then
  echo "  SKIP  mcp_access_tokens table absent (docker compose build webapp && up -d webapp)"
  exit 0
fi

SUF="mcp_$(date +%s)_$$"
U="user_$SUF"
U2="user2_$SUF"
cleanup() {
  q "delete from users where id in ('$U','$U2')" >/dev/null 2>&1
}
trap cleanup EXIT

for uid in "$U" "$U2"; do
  q "insert into users (id, name, email, password, role, created_at, updated_at)
     values ('$uid', 'mcp test', '$uid@test.local', 'bcrypt-placeholder', 'standard', now(), now())" >/dev/null
done

# ------------------------------------------------------------------- ROW 4 ---
echo
echo "-- ROW 4: mint / resolve / revoke / expire round-trip --"

# The route stores sha256(plaintext); resolution looks up by that hash alone.
TOK="rdmn_mcp_$(openssl rand -hex 24)"
HASH="$(printf '%s' "$TOK" | sha256sum | cut -d' ' -f1)"
q "insert into mcp_access_tokens (id, user_id, name, token_prefix, token_hash, scopes, created_at)
   values ('t_live_$SUF', '$U', 'live', '${TOK:0:17}', '$HASH', ARRAY['recon:read'], now())" >/dev/null

expect_eq "a minted token resolves by its hash to exactly one user" \
  "$U" "$(q "select user_id from mcp_access_tokens where token_hash = '$HASH'")"

expect_eq "the scopes array round-trips as a text[]" \
  "recon:read" "$(q "select array_to_string(scopes, ',') from mcp_access_tokens where id = 't_live_$SUF'")"

expect_eq "a multi-scope array round-trips in order" \
  "recon:read,recon:scan,recon:overwrite" \
  "$(q "update mcp_access_tokens set scopes = ARRAY['recon:read','recon:scan','recon:overwrite']
        where id = 't_live_$SUF'
        returning array_to_string(scopes, ',')")"

expect_eq "the DEFAULT scope set is read-only" \
  "recon:read" \
  "$(q "insert into mcp_access_tokens (id, user_id, name, token_prefix, token_hash, created_at)
        values ('t_dflt_$SUF', '$U', 'dflt', 'rdmn_mcp_dddddddd', 'hash_dflt_$SUF', now())
        returning array_to_string(scopes, ',')")"

expect_eq "a live token has null revoked_at and null expires_at" \
  "t" "$(q "select revoked_at is null and expires_at is null from mcp_access_tokens where id = 't_live_$SUF'")"

q "update mcp_access_tokens set revoked_at = now() where id = 't_live_$SUF'" >/dev/null
expect_eq "revoke stamps revoked_at without deleting the row" \
  "1|false" "$(q "select count(*) || '|' || bool_and(revoked_at is null) from mcp_access_tokens where id = 't_live_$SUF'")"

q "update mcp_access_tokens set revoked_at = null, expires_at = now() - interval '1 day' where id = 't_live_$SUF'" >/dev/null
expect_eq "an expired token is still present (visible in the list, flagged)" \
  "1" "$(q "select count(*) from mcp_access_tokens where id = 't_live_$SUF'")"

expect_eq "the plaintext is never stored" \
  "0" "$(q "select count(*) from mcp_access_tokens where token_hash = '$TOK' or token_prefix = '$TOK'")"

expect_eq "the stored hash is a 64-char sha256" \
  "64" "$(q "select length(token_hash) from mcp_access_tokens where id = 't_live_$SUF'")"

# ------------------------------------------------------------------- ROW 5 ---
echo
echo "-- ROW 5: unique hash + user cascade --"

DUP="$(q "insert into mcp_access_tokens (id, user_id, name, token_prefix, token_hash, created_at)
          values ('t_dup_$SUF', '$U2', 'dup', 'rdmn_mcp_dupdupdu', '$HASH', now())")"
case "$DUP" in
  *duplicate*|*unique*|*UNIQUE*) ok "a duplicate token_hash is rejected by the unique index" ;;
  *) bad "a duplicate token_hash is rejected" "insert succeeded or failed for another reason: $DUP" ;;
esac

expect_eq "the unique index is on token_hash" \
  "1" "$(q "select count(*) from pg_indexes
            where tablename = 'mcp_access_tokens' and indexdef ilike '%UNIQUE%token_hash%'")"

expect_eq "there is an index on user_id (the list query)" \
  "1" "$(q "select count(*) from pg_indexes
            where tablename = 'mcp_access_tokens' and indexdef ilike '%(user_id)%'")"

q "insert into mcp_access_tokens (id, user_id, name, token_prefix, token_hash, created_at)
   values ('t_casc_$SUF', '$U2', 'casc', 'rdmn_mcp_cccccccc', 'hash_casc_$SUF', now())" >/dev/null
expect_eq "the token exists before the user is deleted" \
  "1" "$(q "select count(*) from mcp_access_tokens where id = 't_casc_$SUF'")"
q "delete from users where id = '$U2'" >/dev/null
expect_eq "deleting a user CASCADES their tokens away (no orphan credential)" \
  "0" "$(q "select count(*) from mcp_access_tokens where id = 't_casc_$SUF'")"

ORPHAN="$(q "insert into mcp_access_tokens (id, user_id, name, token_prefix, token_hash, created_at)
             values ('t_orph_$SUF', 'no_such_user_$SUF', 'orph', 'rdmn_mcp_oooooooo', 'hash_orph_$SUF', now())")"
case "$ORPHAN" in
  *"foreign key"*|*violates*) ok "a token cannot be created for a non-existent user" ;;
  *) bad "a token cannot be created for a non-existent user" "insert unexpectedly succeeded: $ORPHAN" ;;
esac

# ------------------------------------------------------------------- ROW 6 ---
echo
echo "-- ROW 6: a password change revokes every live token, atomically --"

q "delete from mcp_access_tokens where user_id = '$U'" >/dev/null
for n in 1 2 3; do
  q "insert into mcp_access_tokens (id, user_id, name, token_prefix, token_hash, created_at)
     values ('t_pw${n}_$SUF', '$U', 'pw$n', 'rdmn_mcp_pppppp0$n', 'hash_pw${n}_$SUF', now())" >/dev/null
done
# One already revoked: the route's `revokedAt: null` filter must not re-stamp it.
q "update mcp_access_tokens set revoked_at = now() - interval '5 days' where id = 't_pw3_$SUF'" >/dev/null

# The route's transaction: update the password AND revoke in one unit.
q "begin;
   update users set password = 'new-bcrypt-hash' where id = '$U';
   update mcp_access_tokens set revoked_at = now() where user_id = '$U' and revoked_at is null;
   commit;" >/dev/null

expect_eq "every live token is revoked by the password change" \
  "0" "$(q "select count(*) from mcp_access_tokens where user_id = '$U' and revoked_at is null")"
expect_eq "no token row is deleted (they stay visible, flagged)" \
  "3" "$(q "select count(*) from mcp_access_tokens where user_id = '$U'")"
expect_eq "an already-revoked token keeps its ORIGINAL revoked_at (not re-stamped)" \
  "t" "$(q "select revoked_at < now() - interval '1 day' from mcp_access_tokens where id = 't_pw3_$SUF'")"

# Atomicity: a rolled-back password change must revoke nothing. A half-applied
# reset (new password, old tokens live) is worse than either outcome alone.
q "update mcp_access_tokens set revoked_at = null where user_id = '$U'" >/dev/null
q "begin;
   update users set password = 'should-not-stick' where id = '$U';
   update mcp_access_tokens set revoked_at = now() where user_id = '$U' and revoked_at is null;
   rollback;" >/dev/null
expect_eq "a ROLLED-BACK password change revokes nothing" \
  "3" "$(q "select count(*) from mcp_access_tokens where user_id = '$U' and revoked_at is null")"
expect_eq "...and the password is unchanged" \
  "new-bcrypt-hash" "$(q "select password from users where id = '$U'")"

# ------------------------------------------------------------------- ROW 7 ---
echo
echo "-- ROW 7: prune deletes only long-dead rows; live tokens survive --"

q "delete from mcp_access_tokens where user_id = '$U'" >/dev/null
# live: both timestamps NULL -- the row the prune must never touch
q "insert into mcp_access_tokens (id, user_id, name, token_prefix, token_hash, created_at)
   values ('t_pr_live_$SUF', '$U', 'live', 'rdmn_mcp_11111111', 'h_prlive_$SUF', now())" >/dev/null
# recently revoked: inside the window, keep (answers "why did my agent stop")
q "insert into mcp_access_tokens (id, user_id, name, token_prefix, token_hash, revoked_at, created_at)
   values ('t_pr_recent_$SUF', '$U', 'recent', 'rdmn_mcp_22222222', 'h_prrec_$SUF', now() - interval '10 days', now())" >/dev/null
# long revoked / long expired: outside the window, delete
q "insert into mcp_access_tokens (id, user_id, name, token_prefix, token_hash, revoked_at, created_at)
   values ('t_pr_oldrev_$SUF', '$U', 'oldrev', 'rdmn_mcp_33333333', 'h_prold_$SUF', now() - interval '200 days', now())" >/dev/null
q "insert into mcp_access_tokens (id, user_id, name, token_prefix, token_hash, expires_at, created_at)
   values ('t_pr_oldexp_$SUF', '$U', 'oldexp', 'rdmn_mcp_44444444', 'h_prexp_$SUF', now() - interval '200 days', now())" >/dev/null
# expired long ago but NOT revoked, plus revoked long ago but no expiry: the OR arms
q "insert into mcp_access_tokens (id, user_id, name, token_prefix, token_hash, expires_at, created_at)
   values ('t_pr_futexp_$SUF', '$U', 'futexp', 'rdmn_mcp_55555555', 'h_prfut_$SUF', now() + interval '30 days', now())" >/dev/null

# The route's deleteMany, verbatim in SQL (90-day default window).
CUT="now() - interval '90 days'"
q "delete from mcp_access_tokens
   where user_id = '$U' and (revoked_at < $CUT or expires_at < $CUT)" >/dev/null

expect_eq "a LIVE token (both timestamps NULL) survives" \
  "1" "$(q "select count(*) from mcp_access_tokens where id = 't_pr_live_$SUF'")"
expect_eq "a token expiring in the FUTURE survives" \
  "1" "$(q "select count(*) from mcp_access_tokens where id = 't_pr_futexp_$SUF'")"
expect_eq "a recently revoked token survives (still explains the outage)" \
  "1" "$(q "select count(*) from mcp_access_tokens where id = 't_pr_recent_$SUF'")"
expect_eq "a long-revoked token is pruned" \
  "0" "$(q "select count(*) from mcp_access_tokens where id = 't_pr_oldrev_$SUF'")"
expect_eq "a long-expired token is pruned" \
  "0" "$(q "select count(*) from mcp_access_tokens where id = 't_pr_oldexp_$SUF'")"
expect_eq "exactly 3 of 5 survive" \
  "3" "$(q "select count(*) from mcp_access_tokens where user_id = '$U'")"

# Idempotency: running the prune twice leaves the same state.
q "delete from mcp_access_tokens
   where user_id = '$U' and (revoked_at < $CUT or expires_at < $CUT)" >/dev/null
expect_eq "a second prune is a no-op (idempotent)" \
  "3" "$(q "select count(*) from mcp_access_tokens where user_id = '$U'")"

echo
echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
