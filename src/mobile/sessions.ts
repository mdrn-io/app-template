// Mobile sessions and one-time sign-in codes, kept in SQLite. Only hashes of the secrets are
// stored: someone who can read the database still cannot use what is in it.
//
// A refresh token is "rt2.<user key>.<session id>.<secret>.<signature>", and a sign-in code
// "<code id>.<secret>.<signature>". The signature is an HMAC with MOBILE_TOKEN_SECRET, checked
// before anything is read, so a forged or made-up one costs no SQLite read (POST /mobile/token and
// /mobile/revoke take them without a signed-in user, and their rate limit is per instance only).
// The session id then finds the record in one read; the secret is checked against its stored
// hash. Each use replaces the secret (rotation) and keeps the old hash for reuse detection: an old
// refresh token presented again means two parties hold the session, so the whole session is
// revoked.
//
// Refresh tokens issued before they were signed ("rt1.<user key>.<session id>.<secret>") are still
// taken, and cost a read; each is replaced by a signed one when next used. Once every session
// older than this version has expired (REFRESH_TOKEN_SECONDS after you deployed it), `UNSIGNED`
// can be set to false.
//
// Nothing here is kept longer than it is needed: a session ended by logout, revocation or reuse
// is deleted (a missing session answers just as an ended one would), an expired one is deleted
// when its refresh token is next presented, and expired codes are deleted whenever a new code is
// made. These records name your users, and you are their controller.
import { hmacSign, hmacVerify, randomToken, safeEqual, sha256, userKey } from '../crypto.ts';
import type { Env } from '../env.ts';
import { sqlite, ProductError, type StoredRecord } from '../mdrn.ts';
import { CODE_SECONDS, REFRESH_TOKEN_SECONDS, mobileConfig, now } from './tokens.ts';

export interface MobileSession {
  userId: string;
  email: string | null;
  secretHash: string;
  /** Hashes of this session's earlier refresh tokens, newest first. */
  previousHashes: string[];
  createdAt: number;
  expiresAt: number;
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
const PRUNE_CODES = 100;

/** Whether unsigned "rt1." refresh tokens are still taken (see the top of this file). */
const UNSIGNED = true;

const sessions = (key: string) => `mobile_sessions_${key}`;

/** The text with its signature appended; each kind signs under its own prefix, so a signature
 * made for one can never pass as another's. */
async function signed(env: Env, kind: string, text: string) {
  return `${text}.${await hmacSign(mobileConfig(env)!.secret, `${kind}:${text}`)}`;
}

/** Whether `signature` is ours for `text`. Never true while the module is off. */
async function genuine(env: Env, kind: string, text: string, signature: string) {
  const config = mobileConfig(env);
  return config !== null && (await hmacVerify(config.secret, `${kind}:${text}`, signature));
}

// ---------------------------------------------------------------------------------------------
// One-time codes

/** A code for the app to exchange, valid for CODE_SECONDS and only once. */
export async function createCode(env: Env, input: Omit<SignInCode, 'secretHash' | 'expiresAt'>): Promise<string> {
  await pruneCodes(env);
  const secret = randomToken();
  const record = await sqlite.create<SignInCode>(env, CODES, { ...input, secretHash: await sha256(secret), expiresAt: now() + CODE_SECONDS });
  return signed(env, 'code', `${record.id}.${secret}`);
}

/** Deletes codes that expired without being exchanged (the user left at the confirmation page),
 * so the collection holds only codes still in flight. */
async function pruneCodes(env: Env) {
  const at = now();
  const page = await sqlite.list<SignInCode>(env, CODES, { limit: PRUNE_CODES });
  for (const record of page.items) {
    if (record.data.expiresAt > at) continue;
    try {
      await sqlite.remove(env, CODES, record.id, record.version);
    } catch (error) {
      // Taken or pruned by another request meanwhile.
      if (!(error instanceof ProductError && (error.status === 404 || error.status === 409))) throw error;
    }
  }
}

/** Takes a code: it is deleted before anything else is checked, so it can be tried only once,
 * by anyone, whatever the outcome. Null if it is unknown, used or forged. */
export async function takeCode(env: Env, code: string): Promise<SignInCode | null> {
  const [id, secret, signature, extra] = code.split('.');
  if (extra !== undefined || !ID.test(id ?? '') || !SECRET.test(secret ?? '') || !(await genuine(env, 'code', `${id}.${secret}`, signature ?? ''))) return null;
  const record = await sqlite.get<SignInCode>(env, CODES, id);
  if (!record || !safeEqual(await sha256(secret), record.data.secretHash)) return null;
  try {
    await sqlite.remove(env, CODES, record.id, record.version);
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
  const record = await sqlite.create<MobileSession>(env, sessions(key), {
    userId,
    email,
    secretHash: await sha256(secret),
    previousHashes: [],
    createdAt: at,
    expiresAt: at + REFRESH_TOKEN_SECONDS,
  });
  return { sessionId: record.id, refreshToken: await signed(env, 'refresh', `rt2.${key}.${record.id}.${secret}`) };
}

/** The session record, if `userId` owns it. */
export async function sessionRecord(env: Env, userId: string, sessionId: string): Promise<StoredRecord<MobileSession> | null> {
  if (!ID.test(sessionId)) return null;
  const record = await sqlite.get<MobileSession>(env, sessions(await userKey(userId)), sessionId);
  return record && record.data.userId === userId ? record : null;
}

/** The session a refresh token names, and whether its secret is the current one, an earlier
 * one, or neither. */
async function lookup(env: Env, token: string) {
  const [prefix, key, id, secret, signature, extra] = token.split('.');
  if (extra !== undefined || !KEY.test(key ?? '') || !ID.test(id ?? '') || !SECRET.test(secret ?? '')) return null;
  if (prefix === 'rt2') {
    if (!(await genuine(env, 'refresh', `rt2.${key}.${id}.${secret}`, signature ?? ''))) return null;
  } else if (!(UNSIGNED && prefix === 'rt1' && signature === undefined)) return null;
  const record = await sqlite.get<MobileSession>(env, sessions(key), id);
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
    await revoke(env, record.data.userId, record.id);
    console.warn(JSON.stringify({ event: 'refresh_token_reuse', sessionId: record.id }));
    return { ok: false, reason: 'reused' };
  }
  if (record.data.expiresAt <= now()) {
    await revoke(env, record.data.userId, record.id);
    return { ok: false, reason: 'invalid' };
  }
  const secret = randomToken();
  try {
    await sqlite.update<MobileSession>(
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
  return { ok: true, userId: record.data.userId, sessionId: record.id, refreshToken: await signed(env, 'refresh', `rt2.${key}.${record.id}.${secret}`) };
}

/** Ends one session by deleting it. Its refresh token stops working at once; access tokens
 * already issued for it expire within ACCESS_TOKEN_SECONDS (routes that must stop sooner read the
 * session, as the mail route does). */
export async function revoke(env: Env, userId: string, sessionId: string) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const record = await sessionRecord(env, userId, sessionId);
    if (!record) return;
    try {
      await sqlite.remove(env, sessions(await userKey(userId)), sessionId, record.version);
      return;
    } catch (error) {
      // Gone already, or changed (a refresh) since it was read: read it again.
      if (error instanceof ProductError && error.status === 404) return;
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
    const page = await sqlite.list<MobileSession>(env, collection, { limit: 200, cursor });
    for (const record of page.items) {
      if (record.data.userId === userId) await revoke(env, userId, record.id);
    }
    cursor = page.nextCursor ?? undefined;
  } while (cursor);
}

/** Revokes the session a refresh token belongs to, if the token is genuine (current or earlier). */
export async function revokeByToken(env: Env, token: string) {
  const found = await lookup(env, token);
  if (found && found.match !== 'none') await revoke(env, found.record.data.userId, found.record.id);
}
