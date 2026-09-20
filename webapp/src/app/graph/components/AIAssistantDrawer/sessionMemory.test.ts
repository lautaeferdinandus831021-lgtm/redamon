import { describe, it, expect, beforeEach } from 'vitest'
import { saveProjectSession, getProjectSession, clearProjectSession } from './sessionMemory'

describe('sessionMemory — per-project session persistence', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('saves and reads a session id per project', () => {
    saveProjectSession('projA', 'conv-A1')
    saveProjectSession('projB', 'conv-B1')
    expect(getProjectSession('projA')).toBe('conv-A1')
    expect(getProjectSession('projB')).toBe('conv-B1')
  })

  it('returns null for a project that has no saved session', () => {
    expect(getProjectSession('never-opened')).toBeNull()
  })

  it('does NOT leak one project session into another (the reported bug)', () => {
    saveProjectSession('projA', 'conv-A1')
    // switching to a different project must not surface projA's session
    expect(getProjectSession('projB')).toBeNull()
  })

  it('overwrites with the latest selection for the same project', () => {
    saveProjectSession('projA', 'conv-1')
    saveProjectSession('projA', 'conv-2')
    expect(getProjectSession('projA')).toBe('conv-2')
  })

  it('clears only the targeted project (new chat)', () => {
    saveProjectSession('projA', 'conv-A1')
    saveProjectSession('projB', 'conv-B1')
    clearProjectSession('projA')
    expect(getProjectSession('projA')).toBeNull()
    expect(getProjectSession('projB')).toBe('conv-B1')
  })

  it('ignores empty project id or empty conversation id', () => {
    saveProjectSession('', 'conv-x')
    saveProjectSession('projA', '')
    expect(getProjectSession('')).toBeNull()
    expect(getProjectSession('projA')).toBeNull()
  })

  it('uses a project-scoped storage key', () => {
    saveProjectSession('proj-123', 'conv-9')
    expect(localStorage.getItem('whitehat-current-session-proj-123')).toBe('conv-9')
  })
})
