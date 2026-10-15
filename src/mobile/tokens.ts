// The mobile module's settings and its access tokens.
//
// A native app cannot use MDRN's sign-in cookie, so this backend gives it its own credentials:
// - an access token: short-lived (10 minutes), self-contained and signed with
//   MOBILE_TOKEN_SECRET, so checking one costs no Database call;
// - a refresh token: long-lived, stored only as a hash in Database, replaced on every use
//   (rotation), and revoked with its whole session if an old one is ever presented again.
import { base64url, fromBase64url, hmacSign, hmacVerify } from '../crypto.ts';
import type { Env } from '../env.ts';

export const ACCESS_TOKEN_SECONDS = 10 * 60;
export const REFRESH_TOKEN_SECONDS = 30 * 24 * 60 * 60;
export const CODE_SECONDS = 60;

export interface MobileConfig {
  secret: string;
  redirectUris: Set<string>;
}

/** The module's settings, or null when it is off: it needs MOBILE_TOKEN_SECRET (32+ characters)
 * and at least one redirect URI. While it is off every /mobile route answers 404, and bearer
 * tokens are refused. */
export function mobileConfig(env: Env): MobileConfig | null {
  const secret = env.MOBILE_TOKEN_SECRET ?? '';
  const redirectUris = new Set(
    (env.MOBILE_REDIRECT_URIS ?? '')
      .split(',')
      .map(uri => uri.trim())
      .filter(Boolean),
  );
  if (secret.length < 32 || redirectUris.size === 0) return null;
  return { secret, redirectUris };
}

export const now = () => Math.floor(Date.now() / 1000);

interface AccessClaims {
  sub: string;
  sid: string;
  iat: number;
  exp: number;
}

/** "at1.<claims>.<signature>". The prefix lets a server tell its tokens apart, and changes if
 * the format ever does. */
export async function issueAccessToken(secret: string, userId: string, sessionId: string, at = now()) {
  const claims: AccessClaims = { sub: userId, sid: sessionId, iat: at, exp: at + ACCESS_TOKEN_SECONDS };
  const body = `at1.${base64url(new TextEncoder().encode(JSON.stringify(claims)))}`;
  return `${body}.${await hmacSign(secret, body)}`;
}

/** The user and session an access token names, or null if it is not one of ours, was altered,
 * or has expired. */
export async function verifyAccessToken(secret: string, token: string, at = now()) {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'at1' || token.length > 2048) return null;
  const body = `${parts[0]}.${parts[1]}`;
  if (!(await hmacVerify(secret, body, parts[2]))) return null;
  const bytes = fromBase64url(parts[1]);
  if (!bytes) return null;
  let claims: AccessClaims;
  try {
    claims = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
  if (typeof claims.sub !== 'string' || typeof claims.sid !== 'string' || typeof claims.exp !== 'number') return null;
  if (claims.exp <= at) return null;
  return { userId: claims.sub, sessionId: claims.sid };
}
