'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useGvmStatus } from './useGvmStatus'
import { useGithubHuntStatus } from './useGithubHuntStatus'
import { useTrufflehogRuns } from './useTrufflehogRuns'
import { useSupplyChainStatus } from './useSupplyChainStatus'

/**
 * One bundle of live scan state and actions, for surfaces OTHER than the graph
 * page that need the same scan buttons.
 *
 * Why it exists: the graph toolbar's scan cluster is a thin set of buttons over
 * a thick pile of state - ten status/SSE hooks and roughly twenty handlers, all
 * assembled inside graph/page.tsx and handed down as 66 props. None of that is
 * reachable from the project form, so the buttons could not simply be moved.
 *
 * Deliberately NOT wired into graph/page.tsx yet. That page is the app's main
 * view and rewiring it is a separate, riskier change; this hook is additive, so
 * adopting it there later is a refactor that can be verified on its own.
 *
 * Polling is gated on `enabled`, so a form that is not showing the buttons does
 * not open four polls against the orchestrator.
 */

export interface UseScanControlsOptions {
  projectId?: string | null
  enabled?: boolean
  /**
   * Poll period in ms. The graph page is the live view and wants the hooks'
   * default; a secondary surface showing the same four scans only needs to be
   * roughly current, and polling it at the same rate doubles the status traffic
   * against the orchestrator for no extra information.
   */
  pollingInterval?: number
}

export function useScanControls({
  projectId, enabled = true, pollingInterval,
}: UseScanControlsOptions) {
  const on = Boolean(projectId) && enabled
  const id = projectId || ''
  const poll = pollingInterval ? { pollingInterval } : {}

  const gvm = useGvmStatus({ projectId: id, enabled: on, ...poll })
  const githubHunt = useGithubHuntStatus({ projectId: id, enabled: on, ...poll })
  const trufflehog = useTrufflehogRuns({ projectId: id, enabled: on, ...poll })
  const supplyChain = useSupplyChainStatus({ projectId: id, enabled: on, ...poll })

  const [otherScansOpen, setOtherScansOpen] = useState(false)
  const [hasReconData, setHasReconData] = useState(false)
  const [hasGvmData, setHasGvmData] = useState(false)
  // Optimistic like the graph page: assume installed until /available says no,
  // so the button does not flash disabled on every mount.
  const [gvmAvailable, setGvmAvailable] = useState(true)

  // The GVM stack is an optional install (./whitehat.sh install --gvm). Without
  // this the button starts a scan that can only fail.
  useEffect(() => {
    if (!enabled) return
    let cancelled = false
    fetch('/api/gvm/available')
      .then(res => res.json())
      .then(data => { if (!cancelled) setGvmAvailable(data.available ?? false) })
      .catch(() => { if (!cancelled) setGvmAvailable(false) })
    return () => { cancelled = true }
  }, [enabled])

  // Exactly how the graph page decides whether a download button is live: a HEAD
  // against the download route. Re-probed when a scan settles, since that is
  // when an artifact appears.
  const probe = useCallback(async (url: string) => {
    try {
      const res = await fetch(url, { method: 'HEAD' })
      return res.ok
    } catch {
      return false
    }
  }, [])

  useEffect(() => {
    if (!on) { setHasReconData(false); setHasGvmData(false); return }
    let cancelled = false
    void (async () => {
      const [recon, gvmData] = await Promise.all([
        probe(`/api/recon/${id}/download`),
        probe(`/api/gvm/${id}/download`),
      ])
      if (!cancelled) { setHasReconData(recon); setHasGvmData(gvmData) }
    })()
    return () => { cancelled = true }
    // gvm.state?.status is in the deps so finishing a scan reveals its download.
  }, [on, id, probe, gvm.state?.status])

  // The same three-way split the graph toolbar draws its labels from: `busy` is
  // "the container is working", `active` also covers paused (a paused scan still
  // holds its slot), and `running` is the spinner state.
  const gvmStatus = gvm.state?.status ?? 'idle'
  const gvmBusy = gvmStatus === 'running' || gvmStatus === 'starting' || gvmStatus === 'pausing'
  const gvmStopping = gvmStatus === 'stopping'
  const gvmPausing = gvmStatus === 'pausing'
  const gvmPaused = gvmStatus === 'paused'
  const gvmRunning = gvmBusy || gvmStopping
  const gvmActive = gvmRunning || gvmPaused

  const ghStatus = githubHunt.state?.status ?? 'idle'
  const ghBusy = ghStatus === 'running' || ghStatus === 'starting' || ghStatus === 'pausing'
  const ghRunning = ghBusy || ghStatus === 'stopping'
  const ghActive = ghRunning || ghStatus === 'paused'

  const thRunning = trufflehog.isAnyRunning
  const thActive = thRunning || trufflehog.activeRuns.length > 0

  const scStatus = supplyChain.state?.status ?? 'idle'
  const scBusy = scStatus === 'running' || scStatus === 'starting' || scStatus === 'pausing'
  const scActive = scBusy || scStatus === 'stopping' || scStatus === 'paused'

  const downloadReconJSON = useCallback(() => {
    if (projectId) window.open(`/api/recon/${projectId}/download`, '_blank')
  }, [projectId])

  const downloadGvmJSON = useCallback(() => {
    if (projectId) window.open(`/api/gvm/${projectId}/download`, '_blank')
  }, [projectId])

  return useMemo(() => ({
    projectId: projectId ?? null,
    gvm: {
      ...gvm,
      status: gvmStatus,
      isBusy: gvmBusy,
      isRunning: gvmRunning,
      isStopping: gvmStopping,
      isPausing: gvmPausing,
      isPaused: gvmPaused,
      isActive: gvmActive,
      hasData: hasGvmData,
      isAvailable: gvmAvailable,
      download: downloadGvmJSON,
    },
    githubHunt: { ...githubHunt, isBusy: ghBusy, isRunning: ghRunning, isActive: ghActive },
    trufflehog: { ...trufflehog, isRunning: thRunning, isActive: thActive },
    supplyChain: { ...supplyChain, status: scStatus, isBusy: scBusy, isActive: scActive },
    hasReconData,
    downloadReconJSON,
    otherScansOpen,
    openOtherScans: () => setOtherScansOpen(true),
    closeOtherScans: () => setOtherScansOpen(false),
    toggleOtherScans: () => setOtherScansOpen(v => !v),
  }), [
    projectId, gvm, gvmStatus, gvmBusy, gvmRunning, gvmStopping, gvmPausing, gvmPaused, gvmActive,
    githubHunt, ghBusy, ghRunning, ghActive,
    trufflehog, thRunning, thActive,
    supplyChain, scStatus, scBusy, scActive,
    downloadReconJSON, downloadGvmJSON, otherScansOpen, hasReconData, hasGvmData, gvmAvailable,
  ])
}

export type ScanControls = ReturnType<typeof useScanControls>
