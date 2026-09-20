import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

/**
 * Guards a write that hangs off a `userId` foreign key.
 *
 * The browser can hold a user id that no longer exists (a DB reset, a deleted
 * account, a stale `whitehat-current-user` restored on an admin's next visit).
 * Reads for such an id come back as an innocuous empty list, so the first
 * WRITE is where it surfaces - and without this it surfaced as an unhandled
 * Prisma P2003 ("Foreign key constraint violated on user_llm_providers_user_id_fkey")
 * turned into an opaque 500, which is the whole reason issue #173 was
 * unreadable from the UI.
 *
 * Returns a 404 NextResponse the caller must return, or null when the user is
 * real. Call it AFTER the ownership gate so it cannot be used to probe which
 * user ids exist.
 */
export async function requireUserExists(userId: string): Promise<NextResponse | null> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true },
  })
  if (!user) {
    return NextResponse.json(
      { error: 'User not found. Your session points at an account that no longer exists - log out and back in.' },
      { status: 404 }
    )
  }
  return null
}

/**
 * True for the Prisma foreign-key violation code. The existence check above is
 * the fast path; this catches the race where the user is deleted between the
 * check and the insert, so that still reads as a 404 rather than a 500.
 */
export function isForeignKeyViolation(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { code?: unknown }).code === 'P2003'
  )
}
