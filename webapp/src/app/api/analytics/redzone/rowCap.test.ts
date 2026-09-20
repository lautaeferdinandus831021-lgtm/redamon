/**
 * The global RedZone row cap.
 *
 * Every analytics route used to carry its own LIMIT (200 / 500 / 1000 / 2000
 * depending on which file you opened), so the ceiling a table hit was an
 * accident of history rather than a decision. These tests pin the single cap
 * and, structurally, stop a new route from quietly reintroducing its own.
 *
 * Source-level assertions for the structural part, in the same spirit as
 * src/app/graph/tableViewWiring.test.ts: what is being checked is that no file
 * hardcodes a limit, which no amount of calling the handlers can prove.
 *
 * Run: npx vitest run src/app/api/analytics/redzone/rowCap.test.ts
 */
import { describe, test, expect, afterEach } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { REDZONE_ROW_CAP, rowCap } from './rowCap'

const HERE = join(process.cwd(), 'src/app/api/analytics/redzone')

function routeFiles(): { name: string; src: string }[] {
  return readdirSync(HERE, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .map(d => ({ name: d.name, src: readFileSync(join(HERE, d.name, 'route.ts'), 'utf8') }))
}

afterEach(() => {
  delete process.env.WHITEHAT_REDZONE_ROW_CAP
})

describe('the global row cap', () => {
  test('is 200k', () => {
    expect(REDZONE_ROW_CAP).toBe(200_000)
    expect(rowCap()).toBe(200_000)
  })

  test('can be lowered per-process for small hosts', () => {
    process.env.WHITEHAT_REDZONE_ROW_CAP = '5000'
    expect(rowCap()).toBe(5000)
  })

  // A malformed env var must not silently become NaN and produce `LIMIT NaN`,
  // which Neo4j rejects at parse time and would take out every table at once.
  test.each(['', 'lots', '0', '-1', 'NaN', 'Infinity'])(
    'falls back to the default for a junk override (%j)',
    raw => {
      process.env.WHITEHAT_REDZONE_ROW_CAP = raw
      expect(rowCap()).toBe(REDZONE_ROW_CAP)
    },
  )

  test('truncates a fractional override to an integer (Cypher LIMIT takes an Integer)', () => {
    process.env.WHITEHAT_REDZONE_ROW_CAP = '1500.7'
    expect(rowCap()).toBe(1500)
    expect(Number.isInteger(rowCap())).toBe(true)
  })

  // REGRESSION: the guard used to test the value BEFORE flooring, so '0.5'
  // passed (0.5 > 0) and then floored to 0. `LIMIT 0` returns no rows at all,
  // which renders every RedZone table empty while looking like a clean result -
  // the exact failure mode the supply-chain code keeps closing elsewhere.
  test.each(['0.5', '0.9', '0.0001'])(
    'a sub-1 fraction (%j) never becomes LIMIT 0',
    raw => {
      process.env.WHITEHAT_REDZONE_ROW_CAP = raw
      expect(rowCap()).toBe(REDZONE_ROW_CAP)
      expect(rowCap()).toBeGreaterThan(0)
    },
  )

  // REGRESSION: Number('1e21') is finite and positive, but String(1e21) is
  // "1e+21" - exponential notation, which Cypher rejects at parse time. That
  // turns every RedZone route into a 500 rather than a smaller result set.
  test.each(['1e21', '999999999999999999999', '1e308'])(
    'an absurdly large override (%j) still renders as a plain integer literal',
    raw => {
      process.env.WHITEHAT_REDZONE_ROW_CAP = raw
      expect(String(rowCap())).toMatch(/^\d+$/)
      expect(Number.isSafeInteger(rowCap())).toBe(true)
    },
  )

  // A large-but-safe integer is clamped rather than rejected: it is a ceiling,
  // so "more than the maximum" means the maximum, not "back to the default".
  test('clamps a huge but representable override to the ceiling', () => {
    process.env.WHITEHAT_REDZONE_ROW_CAP = '50000000'
    expect(rowCap()).toBe(10_000_000)
    expect(String(rowCap())).toMatch(/^\d+$/)
  })

  test('a value just under the ceiling is passed through untouched', () => {
    process.env.WHITEHAT_REDZONE_ROW_CAP = '9999999'
    expect(rowCap()).toBe(9_999_999)
  })

  // The single invariant the Cypher actually depends on. Whatever an operator
  // types, the interpolated value must be a positive plain-decimal integer that
  // Neo4j can parse and that has not lost precision.
  test.each([
    undefined, '', ' ', '0', '-1', '-0.5', 'lots', 'NaN', 'Infinity', '-Infinity',
    '1_000', '0.5', '1500.7', '  500  ', '1e6', '1e21', '0x10', 'null',
    '999999999999999999999', String(Number.MAX_SAFE_INTEGER), String(Number.MAX_SAFE_INTEGER + 10),
  ])('always yields a Cypher-safe positive integer for %j', raw => {
    if (raw === undefined) delete process.env.WHITEHAT_REDZONE_ROW_CAP
    else process.env.WHITEHAT_REDZONE_ROW_CAP = raw

    const cap = rowCap()
    expect(String(cap), `"LIMIT ${cap}" is not valid Cypher`).toMatch(/^\d+$/)
    expect(Number.isSafeInteger(cap)).toBe(true)
    expect(cap).toBeGreaterThan(0)
  })
})

describe('no route carries its own cap', () => {
  test('the route scan is non-trivial (guards the glob, not the app)', () => {
    expect(routeFiles().length).toBeGreaterThan(15)
  })

  test('no route hardcodes a numeric LIMIT', () => {
    const offenders = routeFiles()
      .filter(r => /LIMIT \d+/.test(r.src))
      .map(r => r.name)
    expect(offenders, `routes with a hardcoded LIMIT: ${offenders.join(', ')}`).toEqual([])
  })

  test('every route that limits rows goes through rowCap()', () => {
    const offenders = routeFiles()
      .filter(r => /\bLIMIT\b/.test(r.src) && !r.src.includes('rowCap()'))
      .map(r => r.name)
    expect(offenders, `routes limiting rows without rowCap(): ${offenders.join(', ')}`).toEqual([])
  })

  // The JS driver sends plain numbers as floats and Cypher's LIMIT demands an
  // Integer, so the cap has to be interpolated into the query text rather than
  // passed as a parameter. supplyChainScaRoute.test.ts pins this for one route;
  // this pins it for all of them.
  test('no route parameterizes LIMIT', () => {
    // `LIMIT $limit` is the bug; `LIMIT ${rowCap()}` is the fix, and it also
    // contains the substring "LIMIT $" - so match a Cypher parameter name
    // (an identifier right after the $), not a JS interpolation (`${`).
    const CYPHER_PARAM_LIMIT = /LIMIT \$[A-Za-z_]/
    const offenders = routeFiles()
      .filter(r => CYPHER_PARAM_LIMIT.test(r.src))
      .map(r => r.name)
    expect(offenders, `routes with a parameterized LIMIT: ${offenders.join(', ')}`).toEqual([])
  })
})
