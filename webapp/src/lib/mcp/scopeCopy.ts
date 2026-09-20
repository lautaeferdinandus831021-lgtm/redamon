/**
 * The operator-facing wording for each token scope.
 *
 * Shared by the token-minting UI and the generated MCP API reference, so the
 * checkbox a person ticks and the page that documents it cannot describe the
 * same permission two different ways.
 *
 * `blurb` is doing two jobs, so the fields are split by AUDIENCE:
 *
 *  - `blurb` is the shared, table-safe text. It becomes ONE MARKDOWN TABLE CELL
 *    in the generated API reference, so it stays to a sentence or two. Changing
 *    it changes `whitehat.wiki/MCP-API-Reference.md`, which means `npm run
 *    docs:mcp` has to run in the same change or apiReference.test.ts goes red.
 *  - `detail` and `learnMore` are UI-only. The renderer never prints them, so
 *    adding or editing either needs no regeneration.
 */
import type { McpScope } from '@/lib/mcpAuth'

export interface ScopeCopy {
  label: string
  /** Table-safe. Printed by the generated API reference. Keep it short. */
  blurb: string
  /** The longer UI paragraph, for a permission that needs a real explanation. */
  detail?: string
  /** A wiki deep link, UI-only. */
  learnMore?: { text: string; href: string }[]
  danger?: boolean
}

const WIKI = 'https://github.com/samugit83/redamon/wiki'

/** Each write scope states its consequence, so a tick is an informed one. */
export const MCP_SCOPE_COPY: Record<McpScope, ScopeCopy> = {
  'recon:read': {
    label: 'Read recon + graph',
    blurb: 'List projects, read scan status and settings, and query the attack-surface graph in natural language.',
  },
  'recon:scan': {
    label: 'Start and stop scans',
    blurb: 'Start a full recon pipeline (keeping the current graph as a saved version) and stop the scan running on a project.',
  },
  'recon:overwrite': {
    label: 'Discard the current graph on start',
    blurb: 'Permits starting a scan in overwrite mode, which DISCARDS the current graph instead of saving it as a version. This is the only irreversible action on this surface.',
    danger: true,
  },
  'recon:settings': {
    label: 'Change recon tuning settings',
    // Two of the four claims this blurb used to make became FALSE when the
    // recon settings registry replaced the allowlist, and one broke in the
    // direction that made the permission sound SAFER than it is. It said "a
    // narrow allowlist" (it is now most of the model) and "never any
    // credential" (graphqlAuthHeader and graphqlAuthValue are open, because
    // scanning an authenticated GraphQL endpoint needs them).
    blurb: 'Change any recon tuning value: per-tool enable flags, rate limits, threads, timeouts, depths, wordlists, templates, severity lists and which phases run, AND the engagement\'s own limits - its rate ceiling, its excluded hosts, its scanning window and the agent\'s denylists. Values are validated and capped at scan start rather than blocked, so the ceiling still wins over anything written here. It cannot point the project at a different target, touch the engagement record, or read a stored credential.',
    detail:
      'Every parameter of the recon pipeline is reachable, and each is controlled ' +
      'by a bound or a validator rather than by being refused by name.\n\n' +
      'Three dispositions decide what a token may write. Most fields are settable ' +
      'at any time, the engagement limits among them. The engagement scope (the ' +
      'target domain, the IP list, the domain batch and the target guardrail) is ' +
      'fixed at creation and is refused here by name. A named set is refused ' +
      'entirely: row identity, the version-activation lock, the Kali-exec flag, ' +
      'the stored CypherFix token, and the engagement RECORD - the client name, ' +
      'the contacts, the dates and the uploaded document.\n\n' +
      'The engagement limits move in EITHER direction here, and that is deliberate. ' +
      'What makes them safe is not a write-time direction rule but that each one is ' +
      'enforced at scan start whatever the setting says. A rate ceiling of 3 still ' +
      'rewrites all 17 rate fields; an excluded host is still dropped in three ' +
      'places. preflight_scope_check reports the resolved configuration, which is ' +
      'the check that actually holds.\n\n' +
      'Three validators are worth knowing about. A container image outside the ' +
      'shipped allowlist is accepted and then pinned back to the default at scan ' +
      'start, so get_recon_settings echoes what was written while the scan runs ' +
      'the safe one. A custom header may not carry CR, LF, Host, Authorization, ' +
      'Cookie or Proxy-*, each of which would change where the request goes ' +
      'rather than annotate it. A wordlist or template path must resolve inside ' +
      'this project\'s own upload directory; anything else is dropped to the ' +
      'shipped default at scan start with a guardrail line recording it.\n\n' +
      'One credential pair is open on purpose: graphqlAuthHeader and ' +
      'graphqlAuthValue are what an operator supplies to scan an authenticated ' +
      'GraphQL endpoint, so they are pipeline configuration. They are WRITE ONLY ' +
      'on this surface - no read tool returns the value.',
  },
  'triage:read': {
    label: 'Read suppressed findings and remediations',
    blurb: 'Read the findings a person muted as noise, including who muted them and why, and the remediation write-ups (their solutions, evidence summaries and PR status). Muted findings are hidden from every other permission on this surface, so this is the only way an agent can tell "nothing was found" apart from "someone suppressed it". Separate from Read recon + graph on purpose: these are not reachable any other way.',
  },
  'recon:queue': {
    label: 'Queue scans to run later',
    blurb: 'Queue a full recon to start when the machine has room, instead of being refused while the project is busy, and cancel a job it queued. A queued job DISPATCHES LATER and is not cancelled when you revoke this token - use the Activity view or the agent\'s own cancel to stop it. It also appears in your queue attributed to you, with nothing marking it as an agent\'s.',
    danger: true,
  },
  'triage:write': {
    label: 'Record a verdict on a finding',
    blurb: 'Let an agent mark a finding confirmed, likely noise, or back to unreviewed, as if you had clicked it yourself. The verdict is DURABLE: it survives re-scans and stops later AI triage runs from overruling it, and the node records that it arrived over MCP. It cannot mute or unmute anything, and nothing on this surface can undo a verdict except another verdict.',
    danger: true,
  },
  'graph:cypher': {
    label: 'Run raw Cypher',
    blurb: 'Send read-only Cypher directly instead of a natural-language question. Still tenant-scoped and still read-only.',
  },
  'project:create': {
    label: 'Create projects and set their engagement scope',
    blurb: 'Create a new project and fix what it points at: its target list and its engagement kind, with its settings and limits applied at creation so the first scan runs configured. Scope is written ONCE at creation and is immutable afterwards through every route on this surface, so this opens new engagements rather than re-pointing existing ones. It governs create_project alone.',
    detail:
      'This is the act that binds WhiteHat to a target, which is why it is its own ' +
      'checkbox rather than part of changing settings. A token with recon:settings ' +
      'can tune the engagements you already have; a token with this one can open ' +
      'new ones.\n\n' +
      'What it can never do is re-point an existing project. The target domain, the ' +
      'address list, the domain batch and the target guardrail are refused by name on ' +
      'a project that already exists, whatever permissions the token holds.\n\n' +
      'It governs create_project and nothing else. An engagement\'s LIMITS - its rate ' +
      'ceiling, its excluded hosts, its scanning window, the agent\'s denylists - are ' +
      'ordinary settings afterwards, changed with recon:settings, and reachable from ' +
      'the project form by a person in exactly the same way. Recording what ' +
      'authorized an engagement is a separate permission again.',
    danger: true,
  },
  'engagement:authorize': {
    label: 'Record what authorized an engagement',
    blurb: 'Attach the scope document that permits an engagement: its digest, its source and the program it came from. The record is APPEND-ONLY and outlives the token that wrote it, so anyone holding this can make a durable claim, in an audit, that a given document authorized a given scan. Separate from creating projects on purpose: writing the audit trail is a different act from configuring the work.',
    detail:
      'Only a DIGEST of the scope document is stored, never the document, so ' +
      'WhiteHat never parses somebody\'s scope prose and the record works the same ' +
      'for a HackerOne policy, a Bugcrowd brief, a signed PDF or an internal ' +
      'ticket.\n\n' +
      'The record cannot be edited or deleted through any path, including this one. ' +
      'When a program changes its scope, a NEW record says the engagement continued ' +
      'under a new authority from that moment, which is what an incident review ' +
      'needs; a row that can be rewritten is not evidence.\n\n' +
      'It carries the id of the token that wrote it, so a revoked credential is ' +
      'still attributable afterwards.',
    danger: true,
  },
  'kali:exec': {
    label: 'Shell access to the Kali sandbox',
    blurb: 'Give the agent a SHELL in the Kali sandbox: `bash -c` with the full toolset, pipelines and redirection, no allowlist and no per-command target check. This is the most powerful permission on this surface and the only one that reaches a live target outside a scan.',
    // Leads with the decision the operator is actually making, because "does my
    // agent bring its own tools or borrow WhiteHat's" is the real question and
    // everything else follows from it.
    //
    // It deliberately does NOT enumerate the toolset. That lives in the
    // kali_shell TOOL_REGISTRY description, which kali_toolbox serves; a list
    // copied into this string would be wrong within a release.
    detail:
      'Does your agent already have security tools installed where it runs, or should it borrow ' +
      'WhiteHat\'s? With this on, your agent runs commands inside WhiteHat\'s Kali sandbox instead of ' +
      'on its own machine, so it needs nothing installed locally. It is the SAME access the in-app ' +
      'agent has: a real shell, the sandbox\'s whole toolset, and no allowlist. Unlike the in-app ' +
      'agent there is no human clicking a confirmation, and commands are NOT checked against this ' +
      'project\'s scope, so an agent you grant this to can reach any host the sandbox can. Tick it ' +
      'only for an agent you would trust with a terminal on that box. It is not sufficient on its ' +
      'own: the deployment must enable the feature and the project must opt in.',
    learnMore: [
      { text: 'What the sandbox carries', href: `${WIKI}/MCP-Server#kali_toolbox-what-the-sandbox-carries` },
      { text: 'What a shell here means', href: `${WIKI}/MCP-Server#kali_exec-a-shell-in-the-sandbox` },
    ],
    danger: true,
  },
}

/**
 * How the checkboxes are GROUPED in the token form.
 *
 * `MCP_SCOPES` is not reordered to achieve this, and must not be: that array is
 * the enforcement list, its per-scope comments carry the security rationale, and
 * its order also drives the generated API reference's permission table. This is
 * a presentation structure beside the copy.
 *
 * With a profile now ticking boxes on the operator's behalf, the list has to be
 * readable at a glance: a flat list of nine, where reading, scanning and writing
 * interleave and the one permission that reaches a live target looks like the
 * eight above it, is not.
 *
 * `tone` drives the visual treatment. `exec` is its own tier rather than more
 * red, because red is already spent on the `danger` scopes inside groups 2 and 3.
 */
export interface ScopeGroup {
  id: string
  label: string
  /** One line saying what the whole group is, so a profile's ticks read as a shape. */
  hint: string
  tone: 'neutral' | 'action' | 'exec'
  scopes: McpScope[]
}

export const SCOPE_GROUPS: ScopeGroup[] = [
  {
    id: 'read',
    label: 'Read and query',
    hint: 'Nothing here changes any state.',
    tone: 'neutral',
    scopes: ['recon:read', 'triage:read', 'graph:cypher'],
  },
  {
    id: 'scan',
    label: 'Run scans',
    hint: 'Start work that writes the attack-surface graph.',
    tone: 'action',
    scopes: ['recon:scan', 'recon:queue', 'recon:overwrite'],
  },
  {
    id: 'write',
    label: 'Change settings and findings',
    hint: 'Writes that are not scans.',
    tone: 'action',
    scopes: ['recon:settings', 'triage:write'],
  },
  {
    id: 'engagement',
    label: 'Open and authorize engagements',
    hint: 'Binds WhiteHat to a target, and records who said it could.',
    tone: 'action',
    scopes: ['project:create', 'engagement:authorize'],
  },
  {
    id: 'exec',
    label: 'Shell access to the sandbox',
    hint: 'A real shell on a target-facing box. Nothing checks what it is aimed at.',
    tone: 'exec',
    scopes: ['kali:exec'],
  },
]
