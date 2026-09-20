/**
 * Preserve the record of what authorized a project, past the project.
 *
 * Every other `Project` child is `onDelete: Cascade`, which would have destroyed
 * the authorization records the moment the project was deleted - the single
 * thing an incident review needs most, gone with the row it was about. The
 * relation is `onDelete: Restrict` instead, so a delete that has not archived
 * them fails rather than silently taking them with it.
 *
 * This is the archiving half. It copies the rows into
 * `engagement_authorization_archive`, sets the session flag the append-only
 * trigger checks, and removes the originals, all inside one transaction, so a
 * failure anywhere leaves both the project and its records intact.
 *
 * The archive table IS a Prisma model, and was deliberately not one until an
 * end-to-end run showed what that cost. `prisma db push --accept-data-loss`
 * drops every table the schema does not know about, and this is the table the
 * delete path must write to before it is allowed to remove a project. Outside
 * the schema it survived only until the next push; in the window between that
 * push and the next webapp boot - which is where the boot script re-creates it -
 * every project holding an authorization record was undeletable, failing with an
 * opaque 500. Since `db push` is how this repo applies schema changes, that
 * window was ordinary working practice.
 *
 * The original reason for keeping it out was that a model would appear in every
 * `select`-building helper that walks the datamodel. No such helper exists: all
 * three callers of `Prisma.dmmf` look up `Project` by name. Nothing in the
 * application reads this table; it is still queried with SQL, by a person,
 * during an investigation.
 */
import prisma from '@/lib/prisma'

export interface ArchiveResult {
  archived: number
  /** Set when the archive could not be written, in which case nothing was removed. */
  error?: string
}

/**
 * Archive and remove a project's authorization records.
 *
 * Returns rather than throws: the caller decides whether a failed archive should
 * stop a delete. It should, and the `Restrict` foreign key enforces that on its
 * own even if a caller forgets - the delete simply fails.
 */
export async function archiveProjectAuthorizations(
  projectId: string,
  reason = 'project_deleted'
): Promise<ArchiveResult> {
  try {
    // Nothing to preserve means nothing to fail on. Checked first so that the
    // common case - every project that predates engagement authorizations, and
    // every internal one - never depends on the archive table existing. A
    // delete blocked because an audit table was missing would be a worse
    // outcome than the one this function is guarding against.
    const existing = await prisma.engagementAuthorization.count({ where: { projectId } })
    if (existing === 0) return { archived: 0 }

    return await prisma.$transaction(async tx => {
      // The trigger refuses every DELETE except one whose session flag names
      // this exact project. `set_config(..., true)` is transaction-local, so the
      // exemption cannot outlive the transaction that needed it.
      await tx.$executeRawUnsafe(
        `SELECT set_config('whitehat.archiving_project', $1, true)`,
        projectId
      )
      const copied = await tx.$executeRawUnsafe(
        `INSERT INTO engagement_authorization_archive (
           id, project_id, document_sha256, document_kind, source_url,
           program_handle, issued_at, recorded_at, recorded_via,
           recorded_by_token_id, recorded_by_user_id, summary, archived_reason
         )
         SELECT id, project_id, document_sha256, document_kind, source_url,
                program_handle, issued_at, recorded_at, recorded_via,
                recorded_by_token_id, recorded_by_user_id, summary, $2
         FROM engagement_authorizations
         WHERE project_id = $1
         ON CONFLICT (id) DO NOTHING`,
        projectId,
        reason
      )
      await tx.$executeRawUnsafe(
        `DELETE FROM engagement_authorizations WHERE project_id = $1`,
        projectId
      )
      return { archived: copied }
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    console.error(`[engagement] could not archive authorizations for ${projectId}:`, message)
    return { archived: 0, error: message }
  }
}
