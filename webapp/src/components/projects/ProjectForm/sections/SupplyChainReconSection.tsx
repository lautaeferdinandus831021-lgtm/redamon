'use client'

import { useState } from 'react'
import { ChevronDown, PackageSearch, Play } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { CredentialShortcut } from '@/components/settings/CredentialShortcut'
import { useCredentialKeys } from '@/hooks/useCredentialKeys'
import {
  HARVESTED_ECOSYSTEM,
  SUPPLY_CHAIN_ECOSYSTEMS,
  SUPPLY_CHAIN_ECOSYSTEM_LABELS,
  parseEcosystems,
  toggleEcosystem,
  unknownEcosystemTokens,
} from './supplyChainEcosystems'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface SupplyChainReconSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

/**
 * L2 - Supply Chain Recon: the recon-pipeline module (GROUP 5.5, after JS Recon).
 * The standalone SBOM/lockfile scan (L1) lives in SupplyChainSection under the
 * "Other Scans" tab; this section is only the pipeline tool.
 */
export function SupplyChainReconSection({ data, updateField, onRun }: SupplyChainReconSectionProps) {
  const keys = useCredentialKeys()
  const [isOpen, setIsOpen] = useState(true)

  const d = data as unknown as {
    supplyChainReconEnabled?: boolean
    supplyChainReconEcosystems?: string
    supplyChainReconDeepAnalysisEnabled?: boolean
    scaIntelCorrelationEnabled?: boolean
    supplyChainTyposquatEnabled?: boolean
  }
  const enabled = !!d.supplyChainReconEnabled
  // Undefined only on a form that predates the field; "" is a real, empty
  // selection (no allow-filter) and must not fall back to the default.
  const storedEcosystems = d.supplyChainReconEcosystems ?? 'npm'
  const selectedEcosystems = parseEcosystems(storedEcosystems)
  const unknownTokens = unknownEcosystemTokens(storedEcosystems)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <PackageSearch size={16} />
          Supply Chain Recon
          <NodeInfoTooltip section="SupplyChainRecon" />
          <WikiInfoButton target="SupplyChainRecon" />
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && enabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: '4px',
                padding: '3px 8px', borderRadius: '4px',
                border: '1px solid rgba(34, 197, 94, 0.3)',
                backgroundColor: 'rgba(34, 197, 94, 0.1)',
                color: '#22c55e', cursor: 'pointer', fontSize: '11px', fontWeight: 500,
              }}
              title="Run Supply Chain Recon"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={enabled}
              onChange={(checked) => updateField('supplyChainReconEnabled' as keyof FormData, checked as never)}
              aria-label="Enable Supply Chain Recon"
            />
          </div>
          <ChevronDown size={16} className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`} />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Works out which packages the target actually ships, without a manifest. It mines package names from
            source maps, module imports, and the detected technology stack, then checks them against a local copy
            of the OSV vulnerability database. Runs after JS Recon and re-uses the JavaScript it already
            downloaded, so it sends no extra traffic to the target, and the verdict is fully offline.
          </p>

          {enabled && (
            <div className={styles.subSection}>
              {/* Repository targets need a token; the recon-sourced package mining
                  above does not. Optional for that reason, and set in place so a
                  private-repo scan is not a round trip to /settings. The GHE pair
                  is inseparable: the host is also the allowlist the token may be
                  sent to, and neither half is usable alone. */}
              <div className={styles.groupHeader}>
                <h3 className={styles.subSectionTitle}>Credentials</h3>
                <p className={styles.fieldHint}>
                  Only needed to reach a private repository. Public repos clone anonymously.
                </p>
              </div>
              <div className={styles.credentialStack}>
                <CredentialShortcut settingsKey="supplyChainGithubToken" keys={keys} optional />
                <CredentialShortcut settingsKey="githubEnterpriseHost" keys={keys} optional />
                <CredentialShortcut settingsKey="githubEnterpriseToken" keys={keys} optional />
              </div>

              <h3 className={styles.subSectionTitle}>Configuration</h3>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Ecosystems</label>
                <p className={styles.fieldHint}>
                  Select the ecosystems to report. Each one must be present in the offline database, populated with{' '}
                  <code>./whitehat.sh supply-chain-sync npm</code> (one sync per ecosystem).
                </p>
                <div className={styles.checkboxGroup} role="group" aria-label="Ecosystems">
                  {SUPPLY_CHAIN_ECOSYSTEMS.map((eco) => (
                    <label key={eco} className="checkboxLabel">
                      <input
                        type="checkbox"
                        className="checkbox"
                        checked={selectedEcosystems.includes(eco)}
                        onChange={() => updateField(
                          'supplyChainReconEcosystems' as keyof FormData,
                          toggleEcosystem(storedEcosystems, eco) as never,
                        )}
                      />
                      {SUPPLY_CHAIN_ECOSYSTEM_LABELS[eco]}
                    </label>
                  ))}
                </div>
                {unknownTokens.length > 0 && (
                  <span className={styles.fieldHint} style={{ color: 'var(--status-warning)' }}>
                    Not an OSV ecosystem, so nothing can ever match it: {unknownTokens.join(', ')}. It is
                    dropped as soon as you change the selection.
                  </span>
                )}
                {selectedEcosystems.length === 0 && unknownTokens.length === 0 && (
                  <span className={styles.fieldHint} style={{ color: 'var(--status-warning)' }}>
                    Nothing selected, so no filter is applied: every harvested package is reported.
                  </span>
                )}
                {selectedEcosystems.length > 0 && !selectedEcosystems.includes(HARVESTED_ECOSYSTEM) && (
                  <span className={styles.fieldHint} style={{ color: 'var(--status-warning)' }}>
                    This module harvests npm packages only, so with npm unticked nothing it harvests is
                    reported. The retire.js pass is not affected by this filter.
                  </span>
                )}
              </div>

              <div className={styles.toggleRow}>
                <div style={{ flex: 1, paddingRight: '12px' }}>
                  <span className={styles.toggleLabel}>Deep behavioural analysis (GuardDog)</span>
                  <p className={styles.toggleDescription} style={{ color: 'var(--status-warning)' }}>
                    Downloads the package archive of a flagged dependency and inspects it inside a hardened,
                    network-isolated sandbox. This reaches out to public package registries, so it stays off unless
                    you specifically need behavioural evidence.
                  </p>
                </div>
                <Toggle
                  checked={!!d.supplyChainReconDeepAnalysisEnabled}
                  onChange={(v) => updateField('supplyChainReconDeepAnalysisEnabled' as keyof FormData, v as never)}
                  aria-label="Deep behavioural analysis"
                />
              </div>

              <div className={styles.toggleRow}>
                <div style={{ flex: 1, paddingRight: '12px' }}>
                  <span className={styles.toggleLabel}>Detect malicious hosts</span>
                  <p className={styles.toggleDescription}>
                    Compares the hosts this scan already saw (the target&apos;s URLs and the servers its JavaScript
                    came from) against a catalog of published supply-chain incidents. Local lookup only: no extra
                    requests, and nothing is sent anywhere. Populate the catalog with
                    {' '}<code>./whitehat.sh sca-intel-sync</code>.
                  </p>
                </div>
                <Toggle
                  // Fallback true, matching the Prisma and Python defaults, so a
                  // project saved before this field existed does not write
                  // undefined the first time the form is touched.
                  checked={d.scaIntelCorrelationEnabled ?? true}
                  onChange={(v) => updateField('scaIntelCorrelationEnabled' as keyof FormData, v as never)}
                  aria-label="Detect malicious hosts"
                />
              </div>

              <div className={styles.toggleRow}>
                <div style={{ flex: 1, paddingRight: '12px' }}>
                  <span className={styles.toggleLabel}>Detect typosquatting</span>
                  <p className={styles.toggleDescription}>
                    Flags harvested package names that are one or two characters away from a popular package without
                    being it. Off by default because near-miss matching can produce false positives; the exact-match
                    check against known-bad names always runs and is unaffected by this switch.
                  </p>
                </div>
                <Toggle
                  checked={d.supplyChainTyposquatEnabled ?? false}
                  onChange={(v) => updateField('supplyChainTyposquatEnabled' as keyof FormData, v as never)}
                  aria-label="Detect typosquatting"
                />
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
