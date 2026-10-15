// Mobile sessions and one-time sign-in codes, kept in Database. Only hashes of the secrets are
// stored: someone who can read the database still cannot use what is in it.
//
// A refresh token is "rt1.<user key>.<session id>.<secret>". The session id finds the record in
// one read; the secret is checked against its stored hash. Each use replaces the secret
// (rotation) and keeps the old hash for reuse detection: an old refresh token presented again
// means two parties hold the session, so the whole session is revoked.
import { randomToken, safeEqual, sha256, userKey } from '../crypto.ts';
import type { Env } from '../env.ts';
import { db, ProductError, type StoredRecord } from '../mdrn.ts';
import { CODE_SECONDS, REFRESH_TOKEN_SECONDS, now } from './tokens.ts';

export interface MobileSession {
  userId: string;
  email: string | null;
  secretHash: string;
  /** Hashes of this session's earlier refresh tokens, newest first. */
  previousHashes: string[];
  createdAt: number;
  expiresAt: number;
  revokedAt: number | null;
  revokedReason: 'logout' | 'reuse' | 'revoked' | null;
}

export interface SignInCode {
  userId: string;
  email: string | null;
  secretHash: string;
  codeChallenge: string;
  redirectUri: string;
  expiresAt: number;
}

const ID = /^[A-Za-z0-9_-]{1,128}$/;
const KEY = /^u[0-9a-f]{32}$/;
const SECRET = /^[A-Za-z0-9_-]{43}$/;
const KEEP_PREVIOUS = 20;
const CODES = 'mobile_codes';

const sessions = (key: string) => `mobile_sessions_${key}`;

// ---------------------------------------------------------------------------------------------
// One-time codes

/** A code for the app to exchange, valid for CODE_SECONDS and only once. */
export async function createCode(env: Env, input: Omit<SignInCode, 'secretHash' | 'expiresAt'>): Promise<string> {
  const secret = randomToken();
  const record = await db.create<SignInCode>(env, CODES, { ...input, secretHash: await sha256(secret), expiresAt: now() + CODE_SECONDS });
  return `${record.id}.${secret}`;
}

/** Takes a code: it is deleted before anything else is checked, so it can be tried only once,
 * by anyone, whatever the outcome. Null if it is unknown, used or forged. */
export async function takeCode(env: Env, code: string): Promise<SignInCode | null> {
  const [id, secret, extra] = code.split('.');
  if (extra !== undefined || !ID.test(id ?? '') || !SECRET.test(secret ?? '')) return null;
  const record = await db.get<SignInCode>(env, CODES, id);
  if (!record || !safeEqual(await sha256(secret), record.data.secretHash)) return null;
  try {
    await db.remove(env, CODES, record.id, record.version);
  } catch (error) {
    // Someone else took it first.
    if (error instanceof ProductError && (error.status === 404 || error.status === 409)) return null;
    throw error;
  }
  return record.data.expiresAt > now() ? record.data : null;
}

// ---------------------------------------------------------------------------------------------
// Sessions

export async function createSession(env: Env, userId: string, email: string | null) {
  const secret = randomToken();
  const key = await userKey(userId);
  const at = now();
  const record = await db.create<MobileSession>(env, sessions(key), {
    userId,
    email,
    secretHash: await sha256(secret),
    previousHashes: [],
    createdAt: at,
    expiresAt: at + REFRESH_TOKEN_SECONDS,
    revokedAt: null,
    revokedReason: null,
  });
  return { sessionId: record.id, refreshToken: `rt1.${key}.${record.id}.${secret}` };
}

/** The session record, if `userId` owns it. */
export async function sessionRecord(env: Env, userId: string, sessionId: string): Promise<StoredRecord<MobileSession> | null> {
  if (!ID.test(sessionId)) return null;
  const record = await db.get<MobileSession>(env, sessions(await userKey(userId)), sessionId);
  return record && record.data.userId === userId ? record : null;
}

/** The session a refresh token names, and whether its secret is the current one, an earlier
 * one, or neither. */
async function lookup(env: Env, token: string) {
  const [prefix, key, id, secret, extra] = token.split('.');
  if (prefix !== 'rt1' || extra !== undefined || !KEY.test(key ?? '') || !ID.test(id ?? '') || !SECRET.test(secret ?? '')) return null;
  const record = await db.get<MobileSession>(env, sessions(key), id);
  if (!record || (await userKey(record.data.userId)) !== key) return null;
  const hash = await sha256(secret);
  const match = safeEqual(hash, record.data.secretHash) ? 'current' : record.data.previousHashes.some(old => safeEqual(hash, old)) ? 'previous' : 'none';
  return { record, hash, match } as const;
}

export type Rotation =
  | { ok: true; userId: string; sessionId: string; refreshToken: string }
  | { ok: false; reason: 'invalid' | 'reused' };

/** Exchanges a refresh token for a new one. The old one stops working at once. */
export async function rotate(env: Env, token: string): Promise<Rotation> {
  const found = await lookup(env, token);
  if (!found || found.match === 'none') return { ok: false, reason: 'invalid' };
  const { record, hash } = found;
  if (found.match === 'previous') {
    // Reuse: this token was already exchanged. Whoever holds the newer one, the session can no
    // longer be trusted, so it ends for both.
    if (!record.data.revokedAt) {
      await revoke(env, record.data.userId, record.id, 'reuse');
      console.warn(JSON.stringify({ event: 'refresh_token_reuse', sessionId: record.id }));
    }
    return { ok: false, reason: 'reused' };
  }
  if (record.data.revokedAt || record.data.expiresAt <= now()) return { ok: false, reason: 'invalid' };
  const secret = randomToken();
  try {
    await db.update<MobileSession>(
      env,
      sessions(await userKey(record.data.userId)),
      record.id,
      { secretHash: await sha256(secret), previousHashes: [hash, ...record.data.previousHashes].slice(0, KEEP_PREVIOUS) },
      record.version,
    );
  } catch (error) {
    // Another refresh with the same token won the race; the app must keep only one in flight.
    if (error instanceof ProductError && error.status === 409) return { ok: false, reason: 'invalid' };
    throw error;
  }
  const key = await userKey(record.data.userId);
  return { ok: true, userId: record.data.userId, sessionId: record.id, refreshToken: `rt1.${key}.${record.id}.${secret}` };
}

/** Ends one session. Its refresh token stops working at once; access tokens already issued for
 * it expire within ACCESS_TOKEN_SECONDS (routes that must stop sooner read the session, as the
 * mail route does). */
export async function revoke(env: Env, userId: string, sessionId: string, reason: MobileSession['revokedReason']) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const record = await sessionRecord(env, userId, sessionId);
    if (!record || record.data.revokedAt) return;
    try {
      await db.update<MobileSession>(env, sessions(await userKey(userId)), sessionId, { revokedAt: now(), revokedReason: reason }, record.version);
      return;
    } catch (error) {
      if (!(error instanceof ProductError && error.status === 409)) throw error;
    }
  }
  throw new Error('Session could not be revoked');
}

/** Ends every mobile session of a user: "sign out everywhere". */
export async function revokeAll(env: Env, userId: string) {
  const collection = sessions(await userKey(userId));
  let cursor: string | undefined;
  do {
    const page = await db.list<MobileSession>(env, collection, { limit: 200, cursor });
    for (const record of page.items) {
      if (record.data.userId === userId && !record.data.revokedAt) await revoke(env, userId, record.id, 'logout');
    }
    cursor = page.nextCursor ?? undefined;
  } while (cursor);
}

/** Revokes the session a refresh token belongs to, if the token is genuine (current or earlier). */
export async function revokeByToken(env: Env, token: string) {
  const found = await lookup(env, token);
  if (found && found.match !== 'none') await revoke(env, found.record.data.userId, found.record.id, 'revoked');
}
