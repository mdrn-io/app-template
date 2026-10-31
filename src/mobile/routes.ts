// Optional mobile module: sign-in for native iOS and Android apps.
//
// Off until you set MOBILE_TOKEN_SECRET and MOBILE_REDIRECT_URIS (see src/env.ts); while off,
// every route here answers 404.
//
// The flow (OAuth 2.0 authorization code with PKCE, RFC 7636):
//  1. The app makes a random code_verifier and its SHA-256, the code_challenge, plus a random
//     state. It opens https://<your app>/mobile/start?redirect_uri=…&code_challenge=…
//     &code_challenge_method=S256&state=… in ASWebAuthenticationSession (iOS) or a Custom Tab
//     (Android). Never in an embedded web view: the user must see the real address bar.
//  2. /mobile/start starts MDRN's hosted sign-in with /mobile/done as the place to come back to.
//  3. Signed in, /mobile/done asks the user to confirm, and /mobile/authorize redirects to the
//     app's redirect_uri with a one-time `code` (valid 60 s) and the same `state`. No token ever
//     appears in a URL.
//  4. The app checks `state`, then POSTs the code with its code_verifier to /mobile/token and
//     gets an access token (10 min) and a refresh token (30 days, rotated on every use).
//  5. API calls send `Authorization: Bearer <access token>`. When it expires, POST the refresh
//     token to /mobile/token. Sign out with POST /mobile/logout.
// A code intercepted on its way to the app is useless without the verifier, which never left it.
import { Hono, type Context } from 'hono';
import { z } from 'zod';
import { identityEmail, requireUser, webUser } from '../auth.ts';
import { randomToken, sha256 } from '../crypto.ts';
import type { AppEnv } from '../env.ts';
import { fail } from '../errors.ts';
import { rateLimit } from '../rate-limit.ts';
import { body, form, query } from '../validate.ts';
import { createCode, createSession, revoke, revokeAll, revokeByToken, rotate, takeCode } from './sessions.ts';
import { ACCESS_TOKEN_SECONDS, issueAccessToken, mobileConfig } from './tokens.ts';

/** What the app sends to start, and what travels with the sign-in until the code is issued. */
const flow = z.strictObject({
  redirect_uri: z.string().min(1).max(512),
  code_challenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/, 'must be the base64url SHA-256 of the code verifier'),
  code_challenge_method: z.literal('S256'),
  state: z.string().regex(/^[A-Za-z0-9._~-]{16,256}$/, 'must be 16 to 256 random URL-safe characters'),
});
type Flow = z.infer<typeof flow>;

const allowedRedirect = (c: Context<AppEnv>, uri: string) => mobileConfig(c.env)!.redirectUris.has(uri);
const flowQuery = (input: Flow) => new URLSearchParams(input).toString();

const escapeHtml = (text: string) =>
  text.replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!);

/** A small page with its own strict Content-Security-Policy: only its own nonce'd script runs. */
function page(c: Context<AppEnv>, title: string, content: string, script = '') {
  const nonce = randomToken();
  c.header('Content-Security-Policy', `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'`);
  c.header('Cache-Control', 'no-store');
  c.header('Referrer-Policy', 'no-referrer');
  return c.html(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style nonce="${nonce}">body{font:16px/1.5 system-ui,sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem}button{font:inherit;padding:.6rem 1.2rem}</style>
</head><body>${content}${script && `<script nonce="${nonce}">${script}</script>`}</body></html>`);
}

export const mobile = new Hono<AppEnv>();

// The whole module is invisible until it is configured.
mobile.use('*', async (c, next) => {
  if (!mobileConfig(c.env)) return fail(c, 404, 'not_found', 'Not found.');
  await next();
});

mobile.get('/start', rateLimit('mobile-start', 20, 60_000, 'address'), query(flow), c => {
  const input = c.req.valid('query');
  if (!allowedRedirect(c, input.redirect_uri)) return fail(c, 400, 'invalid_request', 'redirect_uri is not one this app allows.');
  const done = `/mobile/done?${flowQuery(input)}`;
  // Already signed in to this app in this browser: straight to the confirmation.
  if (webUser(c)) return c.redirect(done, 303);
  // Start MDRN's hosted sign-in with /mobile/done as its return path. This runs in the browser
  // because the sign-in is bound to the browser's own cookies, as it is on the hosted /login.
  const returnPath = JSON.stringify(done).replace(/</g, '\\u003c');
  return page(
    c,
    'Signing in',
    '<p id="status">Opening sign-in…</p>',
    `(async () => {
  try {
    const csrfPath = '/_mdrn/v1/platform/csrf';
    let response = await fetch(csrfPath, { credentials: 'same-origin' });
    if (response.status === 401) response = await fetch(csrfPath, { credentials: 'same-origin' });
    const { csrfToken } = await response.json();
    const started = await fetch('/_mdrn/v1/auth/start', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
      body: JSON.stringify({ returnPath: ${returnPath} }),
    });
    if (!started.ok) throw new Error();
    const target = new URL((await started.json()).url, location.origin);
    if (target.origin !== location.origin) throw new Error();
    location.replace(target.href);
  } catch {
    document.getElementById('status').textContent = 'Sign-in could not start. Close this window and try again.';
  }
})();`,
  );
});

// The confirmation step means a link alone can never hand a code to an app: the signed-in user
// has to press the button on this page, which only this app's own origin can submit.
mobile.get('/done', requireUser('web'), query(flow), c => {
  const input = c.req.valid('query');
  if (!allowedRedirect(c, input.redirect_uri)) return fail(c, 400, 'invalid_request', 'redirect_uri is not one this app allows.');
  const fields = Object.entries(input)
    .map(([name, value]) => `<input type="hidden" name="${name}" value="${escapeHtml(value)}">`)
    .join('');
  return page(c, 'Continue to the app', `<h1>Continue to the app?</h1><p>You are signed in. The app will be signed in as you.</p><form method="post" action="/mobile/authorize">${fields}<button type="submit">Continue</button></form>`);
});

mobile.post('/authorize', requireUser('web'), form(flow), async c => {
  const user = c.get('user');
  const input = c.req.valid('form');
  if (!allowedRedirect(c, input.redirect_uri)) return fail(c, 400, 'invalid_request', 'redirect_uri is not one this app allows.');
  // The address is read from MDRN now, while the browser's session can prove it, and kept with
  // the mobile session for the mail route.
  const email = await identityEmail(c.env, c.req.url, user.identityToken!);
  const code = await createCode(c.env, { userId: user.id, email, codeChallenge: input.code_challenge, redirectUri: input.redirect_uri });
  const target = new URL(input.redirect_uri);
  target.searchParams.set('code', code);
  target.searchParams.set('state', input.state);
  c.header('Cache-Control', 'no-store');
  c.header('Referrer-Policy', 'no-referrer');
  return c.redirect(target.toString(), 303);
});

const tokenRequest = z.discriminatedUnion('grant_type', [
  z.strictObject({
    grant_type: z.literal('authorization_code'),
    code: z.string().min(1).max(256),
    code_verifier: z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/, 'must be 43 to 128 URL-safe characters'),
    redirect_uri: z.string().min(1).max(512),
  }),
  z.strictObject({
    grant_type: z.literal('refresh_token'),
    refresh_token: z.string().min(1).max(512),
  }),
]);

mobile.post('/token', rateLimit('mobile-token', 30, 60_000, 'address'), body(tokenRequest), async c => {
  const { secret } = mobileConfig(c.env)!;
  const input = c.req.valid('json');
  c.header('Cache-Control', 'no-store');
  let userId: string, sessionId: string, refreshToken: string;
  if (input.grant_type === 'authorization_code') {
    const code = await takeCode(c.env, input.code);
    // Every check after the code is taken: a wrong verifier still uses the code up.
    if (!code || code.redirectUri !== input.redirect_uri || code.codeChallenge !== (await sha256(input.code_verifier))) {
      return fail(c, 400, 'invalid_grant', 'The sign-in code is invalid or expired. Sign in again.');
    }
    userId = code.userId;
    ({ sessionId, refreshToken } = await createSession(c.env, code.userId, code.email));
  } else {
    const rotation = await rotate(c.env, input.refresh_token);
    if (!rotation.ok) return fail(c, 400, 'invalid_grant', 'The session has ended. Sign in again.');
    ({ userId, sessionId, refreshToken } = rotation);
  }
  return c.json({
    access_token: await issueAccessToken(secret, userId, sessionId),
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_SECONDS,
    refresh_token: refreshToken,
  });
});

// Revokes a refresh token's session (RFC 7009 style): always 200, so it reveals nothing.
mobile.post('/revoke', rateLimit('mobile-revoke', 30, 60_000, 'address'), body(z.strictObject({ token: z.string().min(1).max(512) })), async c => {
  await revokeByToken(c.env, c.req.valid('json').token);
  return c.json({ revoked: true });
});

// Signs this app session out, or with {"everywhere": true} every mobile session of the user.
mobile.post('/logout', requireUser('mobile'), body(z.strictObject({ everywhere: z.boolean().default(false) })), async c => {
  const user = c.get('user');
  if (c.req.valid('json').everywhere) await revokeAll(c.env, user.id);
  else await revoke(c.env, user.id, user.sessionId!);
  return c.body(null, 204);
});
