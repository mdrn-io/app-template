// Who is calling.
//
// Web: turn on sign-in for the service's origin (in the console, or with
// `mdrn identity enable --origin https://<your app>`). MDRN's Proxy then serves
// the hosted /login page and, on every request from a signed-in browser, adds two headers:
//   x-mdrn-user-id         the user's id
//   x-mdrn-identity-token  a short-lived token for that session, issued by MDRN Identity
// Proxy first deletes every x-mdrn-* header the caller sent, so a client cannot forge them, and
// this Worker is reachable only through Proxy. That is why the headers can be trusted here.
// (Running locally with `wrangler dev` there is no Proxy: anyone can send them. Never expose a
// local server.) MDRN attaches the MDRN_PRODUCTS binding to every release it
// deploys; without it the headers are ignored, so a copy run anywhere else has no web sign-in
// rather than one anybody can forge.
//
// Mobile: a native app sends `Authorization: Bearer <access token>` from src/mobile.
import type { Context } from 'hono';
import { createMiddleware } from 'hono/factory';
import type { AppEnv, Env, SignedInUser } from './env.ts';
import { fail } from './errors.ts';
import { mobileConfig, verifyAccessToken } from './mobile/tokens.ts';

const USER_ID = /^[A-Za-z0-9_-]{1,128}$/;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/** The signed-in browser user, from the headers Proxy added, or null. Null too when this Worker
 * is not running on MDRN (no MDRN_PRODUCTS binding), since nothing then strips forged headers. */
export function webUser(c: Context<AppEnv>): SignedInUser | null {
  if (!c.env?.MDRN_PRODUCTS) return null;
  const id = c.req.header('x-mdrn-user-id');
  const identityToken = c.req.header('x-mdrn-identity-token');
  if (!id || !USER_ID.test(id) || !identityToken) return null;
  return { id, via: 'web', identityToken };
}

/** A cookie-signed-in write must come from this app's own pages. Every app on *.apps.mdrn.io
 * shares that parent domain, and a browser that does not yet treat it as a public suffix sees
 * them all as one "site", so SameSite cookies alone could let another app's page post here with
 * your user's cookie; the Origin header tells them apart in every browser. */
export function sameOrigin(c: Context): boolean {
  const own = new URL(c.req.url).origin;
  const origin = c.req.header('Origin');
  if (origin) return origin === own;
  return c.req.header('Sec-Fetch-Site') === 'same-origin';
}

async function bearerUser(env: Env, authorization: string): Promise<SignedInUser | null> {
  const config = mobileConfig(env);
  const token = /^Bearer ([^\s]+)$/.exec(authorization)?.[1];
  if (!config || !token) return null;
  const claims = await verifyAccessToken(config.secret, token);
  return claims && { id: claims.userId, via: 'mobile', sessionId: claims.sessionId };
}

/** Requires a signed-in user and puts them in c.get('user'). `via` limits which kind. */
export const requireUser = (via: 'web' | 'mobile' | 'any' = 'any') =>
  createMiddleware<AppEnv>(async (c, next) => {
    const authorization = c.req.header('Authorization');
    let user: SignedInUser | null;
    if (authorization !== undefined) {
      // A request with a bearer token is judged by that token alone, never by cookie headers.
      user = via === 'web' ? null : await bearerUser(c.env, authorization);
      if (!user) {
        c.header('WWW-Authenticate', 'Bearer');
        return fail(c, 401, 'unauthenticated', 'Sign in again.');
      }
    } else {
      user = via === 'mobile' ? null : webUser(c);
      if (!user) return fail(c, 401, 'unauthenticated', 'Sign in to continue.');
      if (!SAFE_METHODS.has(c.req.method) && !sameOrigin(c)) {
        return fail(c, 403, 'forbidden', 'This request must come from the app itself.');
      }
    }
    c.set('user', user);
    await next();
  });

/** The signed-in web user's email address, as MDRN Identity knows it, or null when it has none
 * (a Google account need not share one). Asked of MDRN's /v1/auth/me with the session's
 * identity token, through the MDRN_PRODUCTS binding: the address comes from MDRN, never from
 * the client. */
export async function identityEmail(env: Env, requestUrl: string, identityToken: string): Promise<string | null> {
  if (!env.MDRN_PRODUCTS) return null;
  const response = await env.MDRN_PRODUCTS.fetch(
    new Request(new URL('/v1/auth/me', requestUrl), {
      headers: { Authorization: `Bearer ${identityToken}`, Accept: 'application/json' },
      redirect: 'manual',
      signal: AbortSignal.timeout(5_000),
    }),
  );
  if (!response.ok) return null;
  const me: any = await response.json().catch(() => null);
  return typeof me?.email === 'string' && me.email.includes('@') ? me.email : null;
}
