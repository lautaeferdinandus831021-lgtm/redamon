/**
 * Provision the scoped, INSERT-only `traffic_ingest` Postgres role used by the
 * HTTP Traffic Capture ingest worker (plan §5). Runs from the webapp entrypoint
 * IMMEDIATELY AFTER `db push` (the GRANT needs captured_http_transactions to
 * exist) and BEFORE apply-traffic-fts.mjs.
 *
 * WHY THIS EXISTS: the ingest worker connects with TRAFFIC_INGEST_DATABASE_URL,
 * but nothing used to create the matching DB role — so on every fresh install the
 * ingest got a valid DSN yet Postgres rejected it ("password authentication
 * failed"), and captured traffic was silently dropped. This makes the role exist
 * and keeps its password in sync with the DSN on every boot (idempotent, self-
 * healing if the secret is rotated).
 *
 * The password is taken from TRAFFIC_INGEST_DATABASE_URL (generated once by
 * whitehat.sh, the single source of truth). The webapp's DATABASE_URL role is the
 * DB superuser, so CREATE ROLE / GRANT work here.
 */
import { PrismaClient } from '@prisma/client'

const DSN = process.env.TRAFFIC_INGEST_DATABASE_URL || ''

// Escape a value for a single-quoted SQL literal (double any embedded quote).
const sqlLit = (s) => `'${String(s).replace(/'/g, "''")}'`

async function main() {
  if (!DSN) {
    console.log('[ingest-role] TRAFFIC_INGEST_DATABASE_URL unset — skipping (capture ingest not provisioned).')
    return
  }
  let password, user
  try {
    const u = new URL(DSN)
    user = decodeURIComponent(u.username || 'traffic_ingest')
    password = decodeURIComponent(u.password || '')
  } catch (e) {
    console.warn('[ingest-role] could not parse TRAFFIC_INGEST_DATABASE_URL — skipping:', e?.message || e)
    return
  }
  if (user !== 'traffic_ingest') {
    console.warn(`[ingest-role] unexpected role name "${user}" in DSN — expected traffic_ingest; skipping.`)
    return
  }
  if (!password) {
    console.warn('[ingest-role] DSN has no password — skipping (would create a passwordless role).')
    return
  }

  const pw = sqlLit(password)
  // Role first (idempotent create + password sync), then the least-privilege
  // grants: INSERT-only on the capture table, never SELECT (worker never reads
  // traffic back), plus USAGE on the schema so it can name the table.
  const stmts = [
    `DO $$ BEGIN
       IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'traffic_ingest') THEN
         CREATE ROLE traffic_ingest LOGIN PASSWORD ${pw};
       END IF;
     END $$`,
    `ALTER ROLE traffic_ingest LOGIN PASSWORD ${pw}`,
    `REVOKE ALL ON ALL TABLES IN SCHEMA public FROM traffic_ingest`,
    `GRANT USAGE ON SCHEMA public TO traffic_ingest`,
    `GRANT INSERT ON TABLE captured_http_transactions TO traffic_ingest`,
    `REVOKE SELECT ON captured_http_transactions FROM traffic_ingest`,
  ]

  const prisma = new PrismaClient()
  console.log('[ingest-role] provisioning scoped traffic_ingest role...')
  try {
    for (const sql of stmts) {
      await prisma.$executeRawUnsafe(sql)
    }
    console.log('[ingest-role] done (role present, INSERT-only, password in sync).')
  } catch (e) {
    // Never block webapp startup on this — log and continue (capture ingest just
    // won't be able to write until the role is provisioned).
    console.warn('[ingest-role] failed (continuing; capture ingest may not write):', e?.message || e)
  } finally {
    await prisma.$disconnect()
  }
}

main()
