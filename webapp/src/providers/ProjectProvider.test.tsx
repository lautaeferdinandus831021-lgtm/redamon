/**
 * Component tests for ProjectProvider's impersonation client wiring (A7).
 *
 * Proves:
 *  - a standard user NEVER calls the admin-only act-as endpoint (cannot
 *    impersonate client-side)
 *  - an admin restoring an impersonation target from localStorage reconciles the
 *    server act-as cookie on mount, and the effective userId reflects the target
 *  - data loads are GATED behind that reconcile: the project fetch happens AFTER
 *    the act-as call (no race / no stale-cookie 404 under enforcement)
 *  - switching users sets the cookie (POST act-as) and then flips the effective id
 *
 * Run: npx vitest run src/providers/ProjectProvider.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react'
import React from 'react'

// Mutable auth + URL state the mocks read (hoisted-safe: referenced lazily).
let mockAuth: { user: { id: string } | null; isLoading: boolean; isAdmin: boolean } = {
  user: { id: 'me' }, isLoading: false, isAdmin: false,
}
let searchParamsStr = ''

vi.mock('@/providers/AuthProvider', () => ({ useAuth: () => mockAuth }))
vi.mock('next/navigation', () => ({
  useSearchParams: () => new URLSearchParams(searchParamsStr),
  useRouter: () => ({ replace: vi.fn() }),
  usePathname: () => '/graph',
}))

import { ProjectProvider, useProject } from './ProjectProvider'

function Consumer() {
  const { userId, setUserId } = useProject()
  return (
    <div>
      <span data-testid="userId">{userId ?? 'null'}</span>
      <button data-testid="switch" onClick={() => setUserId('userX')}>switch</button>
    </div>
  )
}

type Call = { url: string; method: string; body: string }
let fetchCalls: Call[]

beforeEach(() => {
  fetchCalls = []
  localStorage.clear()
  searchParamsStr = ''
  mockAuth = { user: { id: 'me' }, isLoading: false, isAdmin: false }
  vi.stubGlobal('fetch', vi.fn(async (url: unknown, opts?: RequestInit) => {
    fetchCalls.push({ url: String(url), method: opts?.method ?? 'GET', body: opts?.body ? String(opts.body) : '' })
    return { ok: true, json: async () => ({ id: 'P1' }) } as unknown as Response
  }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const actAsCalls = () => fetchCalls.filter(c => c.url.includes('/api/auth/act-as'))

describe('ProjectProvider impersonation wiring', () => {
  test('standard user: effective id is own, and NEVER calls act-as', async () => {
    mockAuth = { user: { id: 'me' }, isLoading: false, isAdmin: false }
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('me'))
    expect(actAsCalls()).toHaveLength(0)
  })

  test('standard user: setUserId(other) is ignored (stays own, no act-as)', async () => {
    mockAuth = { user: { id: 'me' }, isLoading: false, isAdmin: false }
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('me'))
    fireEvent.click(screen.getByTestId('switch'))
    await new Promise(r => setTimeout(r, 20))
    expect(screen.getByTestId('userId').textContent).toBe('me')
    expect(actAsCalls().some(c => c.method === 'POST')).toBe(false)
  })

  test('admin restoring impersonation from localStorage: POSTs act-as + effective id = target', async () => {
    localStorage.setItem('whitehat-current-user', 'userX')
    mockAuth = { user: { id: 'admin' }, isLoading: false, isAdmin: true }
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() =>
      expect(actAsCalls().some(c => c.method === 'POST' && c.body.includes('userX'))).toBe(true),
    )
    expect(screen.getByTestId('userId').textContent).toBe('userX')
  })

  test('admin not simulating: reconcile clears the cookie (DELETE act-as)', async () => {
    mockAuth = { user: { id: 'admin' }, isLoading: false, isAdmin: true }
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() => expect(actAsCalls().some(c => c.method === 'DELETE')).toBe(true))
    expect(screen.getByTestId('userId').textContent).toBe('admin')
  })

  test('GATE: the project fetch happens AFTER the act-as reconcile (no race)', async () => {
    localStorage.setItem('whitehat-current-user', 'userX')
    searchParamsStr = 'project=P1'
    mockAuth = { user: { id: 'admin' }, isLoading: false, isAdmin: true }
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() => expect(fetchCalls.some(c => c.url.includes('/api/projects/P1'))).toBe(true))
    const actAsIdx = fetchCalls.findIndex(c => c.url.includes('/api/auth/act-as'))
    const projIdx = fetchCalls.findIndex(c => c.url.includes('/api/projects/P1'))
    expect(actAsIdx).toBeGreaterThanOrEqual(0)
    expect(projIdx).toBeGreaterThan(actAsIdx) // load gated behind reconcile
  })

  // Issue #173: the reconcile only caught a network throw, so a 404 ("User not
  // found", the DB was reset / the account was deleted) left the ghost id as the
  // effective user. Reads then returned an empty list and the first WRITE died on
  // the user_id foreign key as an opaque 500 ("Failed to save provider").
  test('admin restoring a DELETED target: falls back to own id and forgets it', async () => {
    localStorage.setItem('whitehat-current-user', 'ghost')
    mockAuth = { user: { id: 'admin' }, isLoading: false, isAdmin: true }
    vi.stubGlobal('fetch', vi.fn(async (url: unknown, opts?: RequestInit) => {
      const u = String(url)
      fetchCalls.push({ url: u, method: opts?.method ?? 'GET', body: opts?.body ? String(opts.body) : '' })
      if (u.includes('/api/auth/act-as') && opts?.method === 'POST') {
        return { ok: false, status: 404, json: async () => ({ error: 'User not found' }) } as unknown as Response
      }
      return { ok: true, json: async () => ({ id: 'P1' }) } as unknown as Response
    }))

    render(<ProjectProvider><Consumer /></ProjectProvider>)

    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('admin'))
    expect(localStorage.getItem('whitehat-current-user')).toBeNull()
    expect(actAsCalls().some(c => c.method === 'DELETE')).toBe(true)
  })

  test('admin switching to a DELETED user: effective id stays own', async () => {
    mockAuth = { user: { id: 'admin' }, isLoading: false, isAdmin: true }
    vi.stubGlobal('fetch', vi.fn(async (url: unknown, opts?: RequestInit) => {
      const u = String(url)
      fetchCalls.push({ url: u, method: opts?.method ?? 'GET', body: opts?.body ? String(opts.body) : '' })
      if (u.includes('/api/auth/act-as') && opts?.method === 'POST') {
        return { ok: false, status: 404, json: async () => ({ error: 'User not found' }) } as unknown as Response
      }
      return { ok: true, json: async () => ({ id: 'P1' }) } as unknown as Response
    }))

    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('admin'))
    fireEvent.click(screen.getByTestId('switch'))

    await waitFor(() =>
      expect(actAsCalls().some(c => c.method === 'POST' && c.body.includes('userX'))).toBe(true),
    )
    await waitFor(() => expect(localStorage.getItem('whitehat-current-user')).toBeNull())
    expect(screen.getByTestId('userId').textContent).toBe('admin')
  })

  test('admin switching users: POST act-as then effective id flips to target', async () => {
    mockAuth = { user: { id: 'admin' }, isLoading: false, isAdmin: true }
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('admin'))
    fireEvent.click(screen.getByTestId('switch'))
    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('userX'))
    expect(actAsCalls().some(c => c.method === 'POST' && c.body.includes('userX'))).toBe(true)
  })
})
