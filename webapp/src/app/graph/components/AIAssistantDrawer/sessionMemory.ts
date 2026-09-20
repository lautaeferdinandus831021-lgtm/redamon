/**
 * Per-project "last active session" memory.
 *
 * The agent drawer tracks a single conversation at a time, but that selection
 * used to be global: switching the project dropdown left the previous project's
 * conversation on screen (and new messages were written to it). This stores the
 * open conversation id per project so a project switch restores THAT project's
 * own session instead of leaking the previous one.
 *
 * Kept as a tiny pure module so it can be unit-tested without React.
 */
const KEY_PREFIX = 'whitehat-current-session-'

function keyFor(projectId: string): string {
  return KEY_PREFIX + projectId
}

/** Remember the conversation currently open for a project. */
export function saveProjectSession(projectId: string, conversationId: string): void {
  if (typeof window === 'undefined' || !projectId || !conversationId) return
  try {
    window.localStorage.setItem(keyFor(projectId), conversationId)
  } catch {
    /* private mode / quota - non-fatal */
  }
}

/** Forget a project's saved session (e.g. on explicit "New chat"). */
export function clearProjectSession(projectId: string): void {
  if (typeof window === 'undefined' || !projectId) return
  try {
    window.localStorage.removeItem(keyFor(projectId))
  } catch {
    /* non-fatal */
  }
}

/** The conversation id a project last had open, or null if none. */
export function getProjectSession(projectId: string): string | null {
  if (typeof window === 'undefined' || !projectId) return null
  try {
    return window.localStorage.getItem(keyFor(projectId))
  } catch {
    return null
  }
}
