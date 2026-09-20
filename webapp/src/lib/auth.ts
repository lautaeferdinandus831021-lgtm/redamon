import { SignJWT, jwtVerify } from 'jose'
import bcrypt from 'bcryptjs'

export const AUTH_COOKIE_NAME = 'whitehat-auth'
const BCRYPT_ROUNDS = 12
const TOKEN_EXPIRY = '7d'

function getSecret() {
  const secret = process.env.AUTH_SECRET
  if (!secret || secret === 'changeme') {
    throw new Error('AUTH_SECRET environment variable is not set')
  }
  return new TextEncoder().encode(secret)
}

export async function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, BCRYPT_ROUNDS)
}

export async function verifyPassword(plain: string, hash: string): Promise<boolean> {
  if (!hash) return false
  return bcrypt.compare(plain, hash)
}

export async function createToken(userId: string, role: string): Promise<string> {
  return new SignJWT({ sub: userId, role })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(TOKEN_EXPIRY)
    .sign(getSecret())
}

export async function verifyToken(token: string): Promise<{ sub: string; role: string } | null> {
  try {
    const { payload } = await jwtVerify(token, getSecret())
    if (!payload.sub || !payload.role) return null
    return { sub: payload.sub, role: payload.role as string }
  } catch {
    return null
  }
}

// --- Agent WebSocket ticket (STRIDE S6) ---------------------------------------
// Short-lived HS256 ticket that binds an authenticated operator identity to a
// (projectId, sessionId) so the agent can verify the /ws/agent init frame. Signed
// with a DEDICATED secret (never AUTH_SECRET) so an agent-side compromise cannot
// forge login cookies. Returns null when the secret is unset, and the agent then
// REFUSES the socket (it fails closed, see agentic/ws_ticket.py) - a stack whose
// .env predates this secret must run ./whitehat.sh update.
const WS_TICKET_EXPIRY = '60s'

function getWsTicketSecret(): Uint8Array | null {
  const secret = process.env.AGENT_WS_TICKET_SECRET
  if (!secret || secret === 'changeme') return null
  return new TextEncoder().encode(secret)
}

export async function createWsTicket(
  userId: string,
  projectId: string,
  sessionId: string
): Promise<string | null> {
  const key = getWsTicketSecret()
  if (!key) return null
  return new SignJWT({ sub: userId, pid: projectId, sid: sessionId })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(WS_TICKET_EXPIRY)
    .sign(key)
}

// --- Admin impersonation "act-as" token (per-user access control) -------------
// Records which user an ADMIN is currently simulating, in a dedicated httpOnly
// cookie. Unlike the ws-ticket (which is sent to the agent), this token is minted
// AND verified only inside the webapp, so reusing AUTH_SECRET is safe. It is
// mutually non-substitutable with the login JWT by claim shape: a login token has
// `role` and no `act`; an act-as token has `act` and no `role`. getEffectiveUser
// only honors it when the caller's real role (from the untouched login JWT) is
// admin AND the token's `sub` equals that admin's id - so a standard user forging
// this cookie is ignored, and a login cookie replayed here fails the `act` check.
export const ACT_AS_COOKIE_NAME = 'whitehat-act-as'
const ACT_AS_EXPIRY = '12h'

export async function createActAsToken(adminUserId: string, targetUserId: string): Promise<string> {
  return new SignJWT({ sub: adminUserId, act: targetUserId })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(ACT_AS_EXPIRY)
    .sign(getSecret())
}

export async function verifyActAsToken(token: string): Promise<{ sub: string; act: string } | null> {
  try {
    const { payload } = await jwtVerify(token, getSecret())
    if (!payload.sub || typeof payload.act !== 'string' || !payload.act) return null
    return { sub: payload.sub as string, act: payload.act }
  } catch {
    return null
  }
}
