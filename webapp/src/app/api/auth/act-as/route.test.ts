/**
 * Unit tests for the admin-only act-as (impersonation) endpoint.
 *
 * Run: npx vitest run src/app/api/auth/act-as/route.test.ts
 *
 * @vitest-environment node
 */

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'c'.repeat(64))

const mockRequireAdmin = vi.fn()
vi.mock('@/lib/session', () => ({
  requireAdmin: () => mockRequireAdmin(),
}))

const mockUserFindUnique = vi.fn()
vi.mock('@/lib/prisma', () => ({
  default: { user: { findUnique: (a: unknown) => mockUserFindUnique(a) } },
}))

const mockWriteActAsAudit = vi.fn().mockResolvedValue(undefined)
vi.mock('@/lib/audit', () => ({
  writeActAsAudit: (a: unknown) => mockWriteActAsAudit(a),
  writeAudit: vi.fn(),
}))

import { POST, DELETE } from './route'

function req(body?: unknown): NextRequest {
  return new NextRequest('http://localhost:3000/api/auth/act-as', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('POST /api/auth/act-as', () => {
  test('non-admin -> passes through requireAdmin 403', async () => {
    mockRequireAdmin.mockResolvedValue(NextResponse.json({ error: 'Forbidden' }, { status: 403 }))
    const res = await POST(req({ targetUserId: 'user-X' }))
    expect(res.status).toBe(403)
  })

  test('admin acting as an existing user -> sets httpOnly act-as cookie', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    mockUserFindUnique.mockResolvedValue({ id: 'user-X' })
    const res = await POST(req({ targetUserId: 'user-X' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ actingAs: 'user-X' })
    const setCookie = res.headers.get('set-cookie') || ''
    expect(setCookie).toContain('whitehat-act-as=')
    expect(setCookie).toMatch(/HttpOnly/i)
  })

  test('writes act-as audit on mint', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    mockUserFindUnique.mockResolvedValue({ id: 'user-X' })
    await POST(req({ targetUserId: 'user-X' }))
    expect(mockWriteActAsAudit).toHaveBeenCalledWith(
      expect.objectContaining({ adminId: 'admin-1', targetUserId: 'user-X', event: 'start' })
    )
  })

  test('writes act-as end audit on self-clear', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    await POST(req({ targetUserId: 'admin-1' }))
    expect(mockWriteActAsAudit).toHaveBeenCalledWith(
      expect.objectContaining({ adminId: 'admin-1', event: 'end' })
    )
  })

  test('admin acting as a nonexistent user -> 404', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    mockUserFindUnique.mockResolvedValue(null)
    const res = await POST(req({ targetUserId: 'ghost' }))
    expect(res.status).toBe(404)
  })

  test('missing targetUserId -> 400', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    const res = await POST(req({}))
    expect(res.status).toBe(400)
  })

  test('acting as self -> clears the cookie (stop simulating)', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    const res = await POST(req({ targetUserId: 'admin-1' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ actingAs: null })
    expect(res.headers.get('set-cookie') || '').toMatch(/Max-Age=0/i)
  })
})

describe('DELETE /api/auth/act-as', () => {
  test('non-admin -> 403', async () => {
    mockRequireAdmin.mockResolvedValue(NextResponse.json({ error: 'Forbidden' }, { status: 403 }))
    const res = await DELETE(req())
    expect(res.status).toBe(403)
  })

  test('admin -> clears the cookie', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    const res = await DELETE(req())
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ actingAs: null })
    expect(res.headers.get('set-cookie') || '').toMatch(/Max-Age=0/i)
  })
})
