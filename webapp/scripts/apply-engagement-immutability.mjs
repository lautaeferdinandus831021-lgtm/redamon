/**
 * Make `engagement_authorizations` append-only in Postgres.
 *
 * The model is the record of WHAT AUTHORIZED an engagement, and it is only
 * evidence if it cannot be rewritten. An agent holding `engagement:authorize`
 * can make a durable claim that a given document permitted a given scan; a row
 * it could later edit would let it unmake that claim after the fact, which is
 * the one property the model exists to have.
 *
 * Prisma has no immutability primitive, so saying "append-only" in a model
 * comment is documentation rather than enforcement. This is the enforcement: a
 * trigger that raises on UPDATE and DELETE, so the rule holds against the ORM,
 * against psql, and against a future code path nobody has written yet.
 *
 * It runs from the webapp entrypoint AFTER `db push`, for the same reason
 * apply-ingest-role.mjs and apply-traffic-fts.mjs do: the push drops objects it
 * does not know about, so anything added outside the Prisma schema has to be
 * re-applied on every boot. Idempotent by construction.
 *
 * The one deliberate hole: deleting the PROJECT. Every other Project child
 * cascades, which would have destroyed the record of what authorized a project
 * the moment the project was deleted - the thing an incident review needs most.
 * The relation is `onDelete: Restrict` instead, and the delete path copies the
 * rows to `engagement_authorization_archive` first. That copy is what the DELETE
 * exemption below is for, and it is scoped to exactly that: a session that has
 * set `whitehat.archiving_project`.
 */
import { PrismaClient } from '@prisma/client'

const TABLE = 'engagement_authorizations'
const ARCHIVE = 'engagement_authorization_archive'

async function main() {
  const prisma = new PrismaClient()
  try {
    // The archive first: the trigger's DELETE exemption is only safe if there
    // is somewhere for the rows to go.
    await prisma.$executeRawUnsafe(`
      CREATE TABLE IF NOT EXISTS ${ARCHIVE} (
        id                   TEXT PRIMARY KEY,
        project_id           TEXT NOT NULL,
        document_sha256      TEXT NOT NULL,
        document_kind        TEXT NOT NULL,
        source_url           TEXT NOT NULL DEFAULT '',
        program_handle       TEXT,
        issued_at            TIMESTAMP(3) NOT NULL,
        recorded_at          TIMESTAMP(3) NOT NULL,
        recorded_via         TEXT NOT NULL,
        recorded_by_token_id TEXT,
        recorded_by_user_id  TEXT,
        summary              TEXT NOT NULL DEFAULT '',
        archived_at          TIMESTAMP(3) NOT NULL DEFAULT NOW(),
        archived_reason      TEXT NOT NULL DEFAULT 'project_deleted'
      )
    `)
    await prisma.$executeRawUnsafe(
      `CREATE INDEX IF NOT EXISTS ${ARCHIVE}_project_idx ON ${ARCHIVE} (project_id)`
    )

    await prisma.$executeRawUnsafe(`
      CREATE OR REPLACE FUNCTION whitehat_engagement_authorizations_append_only()
      RETURNS trigger AS $$
      BEGIN
        IF TG_OP = 'UPDATE' THEN
          RAISE EXCEPTION
            'engagement_authorizations is append-only: an authorization record cannot be '
            'changed after it is written. Record a new one instead; the history of what was '
            'authorized when is the point.'
            USING ERRCODE = 'restrict_violation';
        END IF;
        IF TG_OP = 'DELETE' THEN
          -- Deleting a project archives its records first and sets this flag for
          -- that transaction only. Any other DELETE is refused.
          IF current_setting('whitehat.archiving_project', true) IS DISTINCT FROM OLD.project_id THEN
            RAISE EXCEPTION
              'engagement_authorizations is append-only: an authorization record cannot be '
              'deleted. Deleting the project archives them instead.'
              USING ERRCODE = 'restrict_violation';
          END IF;
          RETURN OLD;
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql
    `)

    // DROP then CREATE rather than CREATE OR REPLACE: Postgres has no
    // replace-trigger, and a stale trigger pointing at an older function body
    // would be a rule that silently stopped matching the code.
    await prisma.$executeRawUnsafe(
      `DROP TRIGGER IF EXISTS ${TABLE}_append_only ON ${TABLE}`
    )
    await prisma.$executeRawUnsafe(`
      CREATE TRIGGER ${TABLE}_append_only
      BEFORE UPDATE OR DELETE ON ${TABLE}
      FOR EACH ROW EXECUTE FUNCTION whitehat_engagement_authorizations_append_only()
    `)

    console.log('[engagement] append-only trigger and archive table applied.')
  } catch (err) {
    // Never fatal. A webapp that refuses to boot because an audit trigger could
    // not be created is a worse outcome than one that boots and logs loudly:
    // the code has no update or delete path either way, and this is the second
    // layer rather than the only one.
    console.error('[engagement] could not apply the append-only trigger:', err?.message || err)
  } finally {
    await prisma.$disconnect().catch(() => {})
  }
}

main()
