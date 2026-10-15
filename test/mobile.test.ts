// The mobile sign-in: one-time code with PKCE, rotating refresh tokens, reuse detection,
// revocation and logout.
import { beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { userKey } from '../src/crypto.ts';
import { resetRateLimits } from '../src/rate-limit.ts';
import { call, fakeMdrn, ORIGIN, type Fake } from './fake-mdrn.ts';

beforeEach(() => resetRateLimits());

const REDIRECT = 'com.example.app:/signed-in';
const settings = { MOBILE_TOKEN_SECRET: 'm'.repeat(48), MOBILE_REDIRECT_URIS: `${REDIRECT}, https://example.com/app/signed-in` };

/** What the native app does before opening the browser. */
function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const state = randomBytes(16).toString('base64url');
  return { verifier, state, flow: { redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256', state } };
}

/** The browser part: the user is signed in to the app and presses Continue. Answers the code. */
async function authorize(fake: Fake, userId: string, flow: Record<string, string>, email?: string) {
  const web = { id: userId, token: fake.signIn(userId, email) };
  const response = await call(fake, 'POST', '/mobile/authorize', new URLSearchParams(flow), { web, origin: ORIGIN });
  assert.equal(response.status, 303);
  const location = new URL(response.headers.get('Location')!);
  return { location, code: location.searchParams.get('code')! };
}

async function signIn(fake: Fake, userId = 'usr_alice', email?: string) {
  const { verifier, flow } = pkce();
  const { code } = await authorize(fake, userId, flow, email);
  const response = await call(fake, 'POST', '/mobile/token', { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: REDIRECT });
  assert.equal(response.status, 200, JSON.stringify(response.body));
  return response.body as { access_token: string; refresh_token: string; expires_in: number; token_type: string };
}

const refresh = (fake: Fake, token: string) => call(fake, 'POST', '/mobile/token', { grant_type: 'refresh_token', refresh_token: token });

test('/mobile/start starts MDRN sign-in with /mobile/done as the return path', async () => {
  const fake = fakeMdrn(settings);
  const { flow } = pkce();
  const response = await call(fake, 'GET', `/mobile/start?${new URLSearchParams(flow)}`);
  assert.equal(response.status, 200);
  const csp = response.headers.get('Content-Security-Policy')!;
  const nonce = /'nonce-([^']+)'/.exec(csp)![1];
  assert.match(response.body, new RegExp(`<script nonce="${nonce}">`));
  assert.ok(response.body.includes('/_mdrn/v1/auth/start'));
  assert.ok(response.body.includes(JSON.stringify(`/mobile/done?${new URLSearchParams(flow)}`)));
});

test('/mobile/start goes straight to the confirmation when the browser is already signed in', async () => {
  const fake = fakeMdrn(settings);
  const { flow } = pkce();
  const response = await call(fake, 'GET', `/mobile/start?${new URLSearchParams(flow)}`, undefined, { web: { id: 'usr_alice', token: fake.signIn('usr_alice') } });
  assert.equal(response.status, 303);
  assert.equal(response.headers.get('Location'), `/mobile/done?${new URLSearchParams(flow)}`);
});

test('only configured redirect URIs, S256 challenges and proper states are accepted', async () => {
  const fake = fakeMdrn(settings);
  const { flow } = pkce();
  for (const change of [{ redirect_uri: 'com.evil.app:/steal' }, { redirect_uri: `${REDIRECT}/extra` }, { code_challenge_method: 'plain' }, { code_challenge: 'short' }, { state: 'x' }]) {
    const response = await call(fake, 'GET', `/mobile/start?${new URLSearchParams({ ...flow, ...change })}`);
    assert.equal(response.status, 400, JSON.stringify(change));
  }
});

test('the confirmation page needs a signed-in browser and posts back to this app', async () => {
  const fake = fakeMdrn(settings);
  const { flow } = pkce();
  assert.equal((await call(fake, 'GET', `/mobile/done?${new URLSearchParams(flow)}`)).status, 401);
  const page = await call(fake, 'GET', `/mobile/done?${new URLSearchParams(flow)}`, undefined, { web: { id: 'usr_alice', token: fake.signIn('usr_alice') } });
  assert.equal(page.status, 200);
  assert.match(page.body, /<form method="post" action="\/mobile\/authorize">/);
});

test('a code is issued only on a same-origin confirmation by a signed-in browser', async () => {
  const fake = fakeMdrn(settings);
  const { flow } = pkce();
  const web = { id: 'usr_alice', token: fake.signIn('usr_alice') };
  assert.equal((await call(fake, 'POST', '/mobile/authorize', new URLSearchParams(flow), { web, origin: 'https://evil.apps.mdrn.io' })).status, 403);
  assert.equal((await call(fake, 'POST', '/mobile/authorize', new URLSearchParams(flow), { origin: ORIGIN })).status, 401);
  const tokens = await signIn(fake);
  assert.equal((await call(fake, 'POST', '/mobile/authorize', new URLSearchParams(flow), { bearer: tokens.access_token })).status, 401, 'a mobile token cannot mint codes');
});

test('the redirect carries only a one-time code and the state, never a token', async () => {
  const fake = fakeMdrn(settings);
  const { flow, state } = pkce();
  const { location } = await authorize(fake, 'usr_alice', flow);
  assert.equal(`${location.protocol}${location.pathname}`, REDIRECT);
  assert.deepEqual([...location.searchParams.keys()].sort(), ['code', 'state']);
  assert.equal(location.searchParams.get('state'), state);
  assert.doesNotMatch(location.href, /at1\.|rt1\./);
});

test('the code exchange gives an access token that signs the user in, and a refresh token', async () => {
  const fake = fakeMdrn(settings);
  const tokens = await signIn(fake, 'usr_alice');
  assert.equal(tokens.token_type, 'Bearer');
  assert.equal(tokens.expires_in, 600);
  assert.match(tokens.refresh_token, /^rt1\./);
  const me = await call(fake, 'GET', '/api/me', undefined, { bearer: tokens.access_token });
  assert.deepEqual(me.body, { id: 'usr_alice', via: 'mobile' });
  // The same user's notes, whichever way they signed in.
  await call(fake, 'POST', '/api/notes', { title: 'from the web' }, { web: { id: 'usr_alice', token: fake.signIn('usr_alice') } });
  const notes = await call(fake, 'GET', '/api/notes', undefined, { bearer: tokens.access_token });
  assert.deepEqual(notes.body.items.map((n: any) => n.title), ['from the web']);
});

test('a code works once, only with its verifier and redirect URI, and a failed try uses it up', async () => {
  const fake = fakeMdrn(settings);
  const exchange = (code: string, verifier: string, redirect = REDIRECT) =>
    call(fake, 'POST', '/mobile/token', { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirect });

  const first = pkce();
  const { code } = await authorize(fake, 'usr_alice', first.flow);
  assert.equal((await exchange(code, first.verifier)).status, 200);
  const replay = await exchange(code, first.verifier);
  assert.equal(replay.status, 400);
  assert.equal(replay.body.error.code, 'invalid_grant');

  const second = pkce();
  const stolen = (await authorize(fake, 'usr_alice', second.flow)).code;
  assert.equal((await exchange(stolen, pkce().verifier)).status, 400, 'an intercepted code is useless without the verifier');
  assert.equal((await exchange(stolen, second.verifier)).status, 400, 'and that failed try used it up');

  const third = pkce();
  const elsewhere = (await authorize(fake, 'usr_alice', third.flow)).code;
  assert.equal((await exchange(elsewhere, third.verifier, 'https://example.com/app/signed-in')).status, 400);

  const [id] = code.split('.');
  assert.equal((await exchange(`${id}.${'A'.repeat(43)}`, first.verifier)).status, 400, 'a forged secret');
});

test('an expired code is refused', async () => {
  const fake = fakeMdrn(settings);
  const { flow, verifier } = pkce();
  const { code } = await authorize(fake, 'usr_alice', flow);
  const record = fake.collections.get('mobile_codes')!.get(code.split('.')[0])!;
  record.data.expiresAt = Math.floor(Date.now() / 1000) - 1;
  const response = await call(fake, 'POST', '/mobile/token', { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: REDIRECT });
  assert.equal(response.status, 400);
});

test('refresh tokens are stored only as hashes', async () => {
  const fake = fakeMdrn(settings);
  const tokens = await signIn(fake, 'usr_alice');
  const secret = tokens.refresh_token.split('.').at(-1)!;
  const stored = JSON.stringify([...fake.collections.get(`mobile_sessions_${await userKey('usr_alice')}`)!.values()]);
  assert.ok(!stored.includes(secret));
});

test('refresh rotates: a new pair each time, and the old refresh token stops working', async () => {
  const fake = fakeMdrn(settings);
  const first = await signIn(fake);
  const second = await refresh(fake, first.refresh_token);
  assert.equal(second.status, 200);
  assert.notEqual(second.body.refresh_token, first.refresh_token);
  assert.equal((await call(fake, 'GET', '/api/me', undefined, { bearer: second.body.access_token })).status, 200);
  const third = await refresh(fake, second.body.refresh_token);
  assert.equal(third.status, 200);
});

test('reusing a rotated refresh token revokes the whole session', async () => {
  const fake = fakeMdrn(settings);
  const first = await signIn(fake);
  const second = (await refresh(fake, first.refresh_token)).body;
  // An attacker replays the old token: refused, and the session ends for everyone.
  const reused = await refresh(fake, first.refresh_token);
  assert.equal(reused.status, 400);
  assert.equal(reused.body.error.code, 'invalid_grant');
  assert.equal((await refresh(fake, second.refresh_token)).status, 400, 'the legitimate holder must sign in again too');
  const sessions = [...fake.collections.get(`mobile_sessions_${await userKey('usr_alice')}`)!.values()];
  assert.equal(sessions[0].data.revokedReason, 'reuse');
});

test('a malformed or forged refresh token is refused without ending the session', async () => {
  const fake = fakeMdrn(settings);
  const tokens = await signIn(fake);
  const [prefix, key, id] = tokens.refresh_token.split('.');
  for (const token of ['nope', `${prefix}.${key}.${id}.${'B'.repeat(43)}`, `${prefix}.u${'0'.repeat(32)}.${id}.${'B'.repeat(43)}`, `${tokens.refresh_token}.x`]) {
    assert.equal((await refresh(fake, token)).status, 400, token);
  }
  assert.equal((await refresh(fake, tokens.refresh_token)).status, 200);
});

test('revoking a refresh token ends its session', async () => {
  const fake = fakeMdrn(settings);
  const tokens = await signIn(fake);
  const response = await call(fake, 'POST', '/mobile/revoke', { token: tokens.refresh_token });
  assert.equal(response.status, 200);
  assert.equal((await refresh(fake, tokens.refresh_token)).status, 400);
  // Revoking something unknown says the same, revealing nothing.
  assert.equal((await call(fake, 'POST', '/mobile/revoke', { token: 'rt1.nothing' })).status, 200);
});

test('logout ends this session; logout everywhere ends them all', async () => {
  const fake = fakeMdrn(settings);
  const phone = await signIn(fake);
  const tablet = await signIn(fake);
  assert.equal((await call(fake, 'POST', '/mobile/logout', undefined, { bearer: phone.access_token })).status, 204);
  assert.equal((await refresh(fake, phone.refresh_token)).status, 400);
  assert.equal((await refresh(fake, tablet.refresh_token)).status, 200, 'the other device is still signed in');

  const laptop = await signIn(fake);
  const watch = await signIn(fake);
  assert.equal((await call(fake, 'POST', '/mobile/logout', { everywhere: true }, { bearer: laptop.access_token })).status, 204);
  assert.equal((await refresh(fake, watch.refresh_token)).status, 400);
  assert.equal((await call(fake, 'POST', '/mobile/logout', undefined, { web: { id: 'usr_alice', token: fake.signIn('usr_alice') } })).status, 401, 'logout is for mobile tokens');
});

test('mail from the app goes to the address read at sign-in, and stops at once on logout', async () => {
  const fake = fakeMdrn(settings);
  const tokens = await signIn(fake, 'usr_alice', 'alice@example.com');
  const message = { subject: 'Hi', text: 'From my phone' };
  assert.equal((await call(fake, 'POST', '/api/mail/me', message, { bearer: tokens.access_token })).status, 202);
  assert.deepEqual(fake.sent.map(m => m.recipient), ['alice@example.com']);
  await call(fake, 'POST', '/mobile/logout', undefined, { bearer: tokens.access_token });
  assert.equal((await call(fake, 'POST', '/api/mail/me', message, { bearer: tokens.access_token })).status, 409);
  assert.equal(fake.sent.length, 1);
});
