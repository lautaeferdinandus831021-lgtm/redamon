/**
 * The global row cap for every RedZone analytics query.
 *
 * Each route used to carry its own hand-picked LIMIT (200 for sharedInfra, 500
 * for most, 1000/2000 for a few), which meant the ceiling a table hit depended
 * on which table it was, and nothing said so on screen. There is now one number
 * for all of them.
 *
 * Read lazily rather than captured at module load so the value can be lowered
 * per-process (small hosts, tests) without an import-order dance:
 *
 *   WHITEHAT_REDZONE_ROW_CAP=5000 docker compose up -d webapp
 *
 * Sizing note: the webapp container is capped at 1g (docker-compose.yml,
 * `mem_limit: ${WEBAPP_MEM:-1g}`) and the Neo4j driver buffers a whole result
 * set in memory before the route maps it. 200k rows of a wide table is a real
 * fraction of that budget, so this is a safety ceiling, not a target - the
 * lever that actually keeps result sets small is the query, not this constant.
 */
export const REDZONE_ROW_CAP = 200_000

/**
 * Hard ceiling on the override. Not a policy limit so much as an arithmetic
 * one: the value is interpolated into Cypher as a literal, and anything past
 * Number.MAX_SAFE_INTEGER either loses precision or stringifies to exponential
 * notation ("1e+21"), which Neo4j rejects at parse time - turning every RedZone
 * route into a 500. 10M is already orders of magnitude past what the 1g webapp
 * container can hold, so clamping here costs nothing real.
 */
const MAX_ROW_CAP = 10_000_000

/**
 * The interpolated value must satisfy three things at once, and the obvious
 * one-liner satisfies only the first:
 *
 *   1. positive, so tables are not silently emptied,
 *   2. an INTEGER, because Cypher's LIMIT rejects floats,
 *   3. renderable as plain decimal digits, because `LIMIT 1e+21` is a parse error.
 *
 * Floor FIRST and validate after: checking `raw > 0` before flooring let '0.5'
 * through, which then floored to 0 and emitted `LIMIT 0` - every RedZone table
 * empty, and empty reads as "nothing found" rather than "misconfigured".
 * Any input that cannot produce a safe positive integer falls back to the
 * default rather than guessing.
 */
export function rowCap(): number {
  const parsed = Math.floor(Number(process.env.WHITEHAT_REDZONE_ROW_CAP))
  if (!Number.isSafeInteger(parsed) || parsed < 1) return REDZONE_ROW_CAP
  return Math.min(parsed, MAX_ROW_CAP)
}
