/**
 * The Agent Onboarding modal.
 *
 * The failure this file owns is silent and plausible: the modal is a singleton
 * rendered by the tab and reopened against a DIFFERENT token each time. If it
 * seeded its state only on first mount, the second operator to press "Onboard"
 * would get a pack describing the PREVIOUS token's profile and permissions,
 * with nothing on screen saying so. They would hand their agent instructions
 * for a credential it does not hold, and every call the pack taught would be
 * refused at run time.
 *
 * It also pins the one thing the modal must say out loud: it generates a
 * document and grants nothing, because the permissions in it are editable and
 * would otherwise read as having widened the token.
 *
 * Run: npx vitest run src/components/settings/mcp-tokens/AgentOnboardingModal.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'

const h = vi.hoisted(() => ({ alertError: vi.fn() }))

vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError: h.alertError }),
  // Rendered inline: this file tests the modal's CONTENT, not the shared
  // Modal's portal and focus behaviour, which has its own tests.
  Modal: ({ isOpen, title, children }: { isOpen: boolean; title?: string; children?: ReactNode }) =>
    isOpen ? <div role="dialog" aria-label={title}>{children}</div> : null,
  ExternalLink: ({ href, children }: { href: string; children?: ReactNode }) =>
    <a href={href}>{children}</a>,
}))

import type React from 'react'
import type { ReactNode } from 'react'
import type { McpScope } from '@/lib/mcpAuth'
import { scopesForProfile } from '@/lib/mcp/profiles'
import AgentOnboardingModal from './AgentOnboardingModal'

type ModalProps = React.ComponentProps<typeof AgentOnboardingModal>

const props = (over: Partial<ModalProps> = {}): ModalProps => ({
  userId: 'owner',
  isOpen: true,
  onClose: vi.fn(),
  initialProfile: null,
  initialScopes: ['recon:read'],
  ...over,
})

const profileSelect = () => screen.getByLabelText('Agent Profile') as HTMLSelectElement

/** Only a checkbox ROW is a label wrapping an input; the footnote is not. */
const box = (scope: McpScope) => {
  const row = screen.getAllByText(scope, { selector: 'code' })
    .map(el => el.closest('label'))
    .find(l => l?.querySelector('input[type=checkbox]'))
  return row!.querySelector('input') as HTMLInputElement
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('fetch', vi.fn(async () => ({
    ok: true,
    status: 200,
    json: async () => ({ files: [{ path: 'SKILL.md', content: '# generated' }] }),
  })))
})

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('it re-seeds when reopened against a different token', () => {
  test('a second open shows the NEW token profile, not the previous one', async () => {
    const { rerender } = render(
      <AgentOnboardingModal {...props({ initialProfile: 'asm', initialScopes: scopesForProfile('asm') })} />
    )
    await waitFor(() => expect(profileSelect().value).toBe('asm'))

    // Closed, then reopened from a different row.
    rerender(<AgentOnboardingModal {...props({ isOpen: false, initialProfile: 'asm', initialScopes: scopesForProfile('asm') })} />)
    rerender(
      <AgentOnboardingModal {...props({ initialProfile: 'triage', initialScopes: scopesForProfile('triage') })} />
    )

    await waitFor(() => expect(profileSelect().value).toBe('triage'))
    expect(box('triage:write'), 'the new token permissions were not picked up').toBeChecked()
    expect(box('recon:queue'), 'the previous token permissions are still shown').not.toBeChecked()
  })

  test('edits made in one session do not survive into the next', async () => {
    // The modal is a preview, so ticking here is expected. It must not leak into
    // the pack generated for the NEXT token.
    const { rerender } = render(
      <AgentOnboardingModal {...props({ initialProfile: 'soc', initialScopes: scopesForProfile('soc') })} />
    )
    await waitFor(() => expect(profileSelect().value).toBe('soc'))
    fireEvent.click(box('kali:exec'))
    await waitFor(() => expect(box('kali:exec')).toBeChecked())

    rerender(<AgentOnboardingModal {...props({ isOpen: false, initialProfile: 'soc', initialScopes: scopesForProfile('soc') })} />)
    rerender(<AgentOnboardingModal {...props({ initialProfile: 'soc', initialScopes: scopesForProfile('soc') })} />)

    await waitFor(() => expect(profileSelect().value).toBe('soc'))
    expect(box('kali:exec'), 'a preview tick leaked into the next token').not.toBeChecked()
  })

  test('a generated preview is cleared, so it cannot describe the wrong token', async () => {
    const { rerender } = render(
      <AgentOnboardingModal {...props({ initialProfile: 'asm', initialScopes: scopesForProfile('asm') })} />
    )
    fireEvent.click(screen.getByText('Generate'))
    await waitFor(() => expect(screen.getByText('# generated')).toBeTruthy())

    rerender(<AgentOnboardingModal {...props({ isOpen: false })} />)
    rerender(<AgentOnboardingModal {...props({ initialProfile: 'triage', initialScopes: scopesForProfile('triage') })} />)

    await waitFor(() => expect(profileSelect().value).toBe('triage'))
    expect(screen.queryByText('# generated'), 'the previous token pack is still on screen').toBeNull()
  })

  test('a null profile reopens as Custom rather than keeping the last one', async () => {
    const { rerender } = render(
      <AgentOnboardingModal {...props({ initialProfile: 'research', initialScopes: scopesForProfile('research') })} />
    )
    await waitFor(() => expect(profileSelect().value).toBe('research'))

    rerender(<AgentOnboardingModal {...props({ isOpen: false })} />)
    rerender(<AgentOnboardingModal {...props({ initialProfile: null, initialScopes: ['recon:read'] })} />)

    await waitFor(() => expect(profileSelect().value).toBe('custom'))
  })
})

describe('it says what it is', () => {
  test('it states plainly that it grants nothing', () => {
    render(<AgentOnboardingModal {...props()} />)
    expect(
      screen.getByText(/previews what the instructions would say, and grants nothing/)
    ).toBeTruthy()
  })

  test('it keeps Agent Skills and Agent Onboarding apart', () => {
    // Three INBOUND "skill" concepts already exist in the product; without this
    // line the tab reads as a fourth.
    render(<AgentOnboardingModal {...props()} />)
    expect(screen.getByText(/teaches yours/)).toBeTruthy()
  })

  test('a scope set that cannot discover a project is called out', () => {
    // recon:read is what makes a token able to find a projectId at all.
    render(<AgentOnboardingModal {...props({ initialScopes: ['triage:read'] })} />)
    expect(screen.getByText(/the token is effectively inert/i)).toBeTruthy()
  })

  test('a queue permission warns that queued work outlives the token', () => {
    render(<AgentOnboardingModal {...props({ initialScopes: ['recon:read', 'recon:queue'] })} />)
    expect(screen.getByText(/NOT cancelled when you revoke the token/)).toBeTruthy()
  })
})

describe('downloading the pack', () => {
  /**
   * REGRESSION: "Download all" saved only the first file.
   *
   * It looped a single-file download over all five in one tick. A browser
   * refuses a burst of programmatic downloads from one gesture - Chrome prompts
   * once and silently drops the rest - and the object URL was revoked
   * synchronously after click(), racing the browser's read of the blob. On top
   * of that it flattened `references/x.md` to `references-x.md`, destroying the
   * exact layout the install hint tells the operator to build.
   */
  const PACK = [
    { path: 'SKILL.md', content: '# skill' },
    { path: 'references/lifecycle-and-scans.md', content: '# lifecycle' },
    { path: 'references/settings.md', content: '# settings' },
  ]

  let saved: { name: string; blob: Blob }[]

  beforeEach(() => {
    saved = []
    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: true, status: 200, json: async () => ({ files: PACK }),
    })))
    // Capture what the anchor was handed, without letting jsdom navigate.
    // Signature matches the real one (Blob | MediaSource) rather than being cast
    // to fit: a narrowed mock parameter is exactly the kind of cast that hides a
    // real mismatch.
    vi.spyOn(URL, 'createObjectURL').mockImplementation((obj: Blob | MediaSource) => {
      if (obj instanceof Blob) saved.push({ name: '', blob: obj })
      return 'blob:stub'
    })
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined)
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      if (saved.length) saved[saved.length - 1].name = this.download
    })
  })

  const generate = async () => {
    render(<AgentOnboardingModal {...props({ initialProfile: 'bug_bounty' })} />)
    fireEvent.click(screen.getByText('Generate'))
    await waitFor(() => expect(screen.getByText('# skill')).toBeTruthy())
  }

  test('"Download all" produces ONE archive, not one download per file', async () => {
    await generate()
    fireEvent.click(screen.getByText(/Download all 3/))
    await waitFor(() => expect(saved).toHaveLength(1))
    expect(saved[0].name).toBe('whitehat-bug-bounty.zip')
  })

  test('the archive keeps the references/ folder rather than flattening it', async () => {
    const JSZip = (await import('jszip')).default
    await generate()
    fireEvent.click(screen.getByText(/Download all 3/))
    await waitFor(() => expect(saved).toHaveLength(1))

    const entries = Object.keys((await JSZip.loadAsync(saved[0].blob)).files)
      .filter(n => !n.endsWith('/'))
    // The install hint tells the operator to put SKILL.md at the root of a
    // profile-named directory with references/ beneath it. The zip must BE that.
    expect(entries.sort()).toEqual([
      'whitehat-bug-bounty/SKILL.md',
      'whitehat-bug-bounty/references/lifecycle-and-scans.md',
      'whitehat-bug-bounty/references/settings.md',
    ])
    for (const e of entries) expect(e, 'a path was flattened').not.toContain('references-')
  })

  test('the archive content is the generated content, not a placeholder', async () => {
    const JSZip = (await import('jszip')).default
    await generate()
    fireEvent.click(screen.getByText(/Download all 3/))
    await waitFor(() => expect(saved).toHaveLength(1))

    const zip = await JSZip.loadAsync(saved[0].blob)
    expect(await zip.file('whitehat-bug-bounty/references/settings.md')!.async('string')).toBe('# settings')
  })

  test('a single-file download keeps its basename, unflattened', async () => {
    await generate()
    fireEvent.click(screen.getByText(/Download this file/))
    await waitFor(() => expect(saved).toHaveLength(1))
    expect(saved[0].name).toBe('SKILL.md')
  })

  test('the object URL is NOT revoked synchronously, which would abort the save', async () => {
    await generate()
    fireEvent.click(screen.getByText(/Download this file/))
    await waitFor(() => expect(saved).toHaveLength(1))
    expect(URL.revokeObjectURL).not.toHaveBeenCalled()
  })
})
