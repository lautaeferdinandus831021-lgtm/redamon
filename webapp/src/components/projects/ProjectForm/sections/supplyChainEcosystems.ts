/**
 * Canonical OSV ecosystem names for the Supply Chain Recon allow-filter.
 *
 * The setting travels as a comma-separated string (Prisma
 * `supplyChainReconEcosystems`, default "npm") and is matched EXACTLY against
 * the `ecosystem` of each harvested package in
 * recon/main_recon_modules/supply_chain_recon.py, so casing matters: "pypi"
 * would silently filter everything out. These are the same names as
 * SEED_MANIFESTS in scanners/supply_chain_common/osv_db_sync.py - the only
 * ecosystems `./whitehat.sh supply-chain-sync` can populate offline.
 */
export const SUPPLY_CHAIN_ECOSYSTEMS = [
  'npm',
  'PyPI',
  'Go',
  'Maven',
  'crates.io',
  'Packagist',
  'RubyGems',
  'NuGet',
] as const

export type SupplyChainEcosystem = (typeof SUPPLY_CHAIN_ECOSYSTEMS)[number]

/** Human label per ecosystem, so the checkbox says what the name means. */
export const SUPPLY_CHAIN_ECOSYSTEM_LABELS: Record<SupplyChainEcosystem, string> = {
  npm: 'npm (JavaScript)',
  PyPI: 'PyPI (Python)',
  Go: 'Go',
  Maven: 'Maven (Java)',
  'crates.io': 'crates.io (Rust)',
  Packagist: 'Packagist (PHP)',
  RubyGems: 'RubyGems (Ruby)',
  NuGet: 'NuGet (.NET)',
}

const CANONICAL_BY_LOWER = new Map<string, SupplyChainEcosystem>(
  SUPPLY_CHAIN_ECOSYSTEMS.map((eco) => [eco.toLowerCase(), eco]),
)

/**
 * Stored string -> selected ecosystems, in catalogue order. Case-insensitive
 * and whitespace-tolerant so a value typed in the old free-text field still
 * ticks the right boxes; unknown tokens are dropped (they can never match a
 * harvested package anyway).
 */
export function parseEcosystems(value: string | null | undefined): SupplyChainEcosystem[] {
  const selected = new Set<SupplyChainEcosystem>()
  for (const token of (value ?? '').split(',')) {
    const canonical = CANONICAL_BY_LOWER.get(token.trim().toLowerCase())
    if (canonical) selected.add(canonical)
  }
  return SUPPLY_CHAIN_ECOSYSTEMS.filter((eco) => selected.has(eco))
}

/**
 * The tokens in a stored value that are NOT OSV ecosystems, in the order they
 * appear. They are not a no-op: recon matches them exactly, so a stored
 * "cargo" is a live filter that nothing can ever satisfy (it reports zero
 * packages) - the UI has to say so rather than show an empty selection.
 */
export function unknownEcosystemTokens(value: string | null | undefined): string[] {
  const unknown: string[] = []
  for (const token of (value ?? '').split(',')) {
    const trimmed = token.trim()
    if (trimmed && !CANONICAL_BY_LOWER.has(trimmed.toLowerCase())) unknown.push(trimmed)
  }
  return unknown
}

/**
 * The only ecosystem the L2 harvester can emit: every source in
 * recon/helpers/supply_chain/harvest.py (source maps, module imports,
 * wappalyzer technologies) hardcodes "npm", as does the retire.js pass. A
 * selection without it filters the whole harvested set away.
 */
export const HARVESTED_ECOSYSTEM = 'npm'

/** Selected ecosystems -> stored string, always canonical and in catalogue order. */
export function serializeEcosystems(ecosystems: readonly SupplyChainEcosystem[]): string {
  const selected = new Set(ecosystems)
  return SUPPLY_CHAIN_ECOSYSTEMS.filter((eco) => selected.has(eco)).join(',')
}

/** Flip one ecosystem in the stored string and hand back the new stored string. */
export function toggleEcosystem(
  value: string | null | undefined,
  ecosystem: SupplyChainEcosystem,
): string {
  const selected = new Set(parseEcosystems(value))
  if (selected.has(ecosystem)) {
    selected.delete(ecosystem)
  } else {
    selected.add(ecosystem)
  }
  return serializeEcosystems([...selected])
}
