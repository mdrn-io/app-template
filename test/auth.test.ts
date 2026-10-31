// Who may call: MDRN's signed-in browser headers, this backend's own bearer tokens, nobody else.
import { beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { issueAccessToken } from '../src/mobile/tokens.ts';
import { resetRateLimits } from '../src/rate-limit.ts';
import { call, fakeMdrn, ORIGIN } from './fake-mdrn.ts';

const SECRET = 's'.repeat(48);
const mobileOn = { MOBILE_TOKEN_SECRET: SECRET, MOBILE_REDIRECT_URIS: 'com.example.app:/signed-in' };

beforeEach(() => resetRateLimits());

test('health answers without sign-in', async () => {
  const fake = fakeMdrn();
  const response = await call(fake, 'GET', '/health');
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { ok: true });
});

test('an API call without a signed-in user is refused', async () => {
  const fake = fakeMdrn();
  const response = await call(fake, 'GET', '/api/me');
  assert.equal(response.status, 401);
  assert.equal(response.body.error.code, 'unauthenticated');
});

test('the user Proxy names is the caller', async () => {
  const fake = fakeMdrn();
  const response = await call(fake, 'GET', '/api/me', undefined, { web: { id: 'usr_alice', token: fake.signIn('usr_alice') } });
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { id: 'usr_alice', via: 'web' });
  assert.equal(response.headers.get('Cache-Control'), 'private, no-store');
});

test('a user id without the identity token Proxy adds with it is not a sign-in', async () => {
  const fake = fakeMdrn();
  const response = await call(fake, 'GET', '/api/me', undefined, { headers: { 'x-mdrn-user-id': 'usr_alice' } });
  assert.equal(response.status, 401);
});

test('off MDRN (no MDRN_PRODUCTS binding) the sign-in headers are ignored, since nothing strips forged ones', async () => {
  const fake = fakeMdrn({ MDRN_PRODUCTS: undefined });
  const response = await call(fake, 'GET', '/api/me', undefined, { headers: { 'x-mdrn-user-id': 'usr_alice', 'x-mdrn-identity-token': 't' } });
  assert.equal(response.status, 401);
});

test('every answer carries the hardening headers, errors too', async () => {
  const fake = fakeMdrn();
  for (const path of ['/health', '/api/me', '/nothing-here']) {
    const response = await call(fake, 'GET', path);
    assert.equal(response.headers.get('X-Content-Type-Options'), 'nosniff', path);
    assert.equal(response.headers.get('X-Frame-Options'), 'SAMEORIGIN', path);
    assert.equal(response.headers.get('Referrer-Policy'), 'no-referrer', path);
    assert.equal(response.headers.get('Strict-Transport-Security'), 'max-age=15552000', path);
  }
});

test('the address limiter counts per address, and never puts callers of unknown address in one bucket', async () => {
  const fake = fakeMdrn(mobileOn);
  const revoke = (headers: Record<string, string>) => call(fake, 'POST', '/mobile/revoke', { token: 'rt1.nothing' }, { headers });
  for (let i = 0; i < 30; i++) assert.equal((await revoke({ 'CF-Connecting-IP': '192.0.2.1' })).status, 200);
  assert.equal((await revoke({ 'CF-Connecting-IP': '192.0.2.1' })).status, 429);
  assert.equal((await revoke({ 'CF-Connecting-IP': '192.0.2.2' })).status, 200, 'another address has its own window');
  for (let i = 0; i < 40; i++) assert.equal((await revoke({})).status, 200);
});

test('a malformed user id is refused', async () => {
  const fake = fakeMdrn();
  for (const id of ['', 'usr alice', 'usr/../alice', 'x'.repeat(129)]) {
    const response = await call(fake, 'GET', '/api/me', undefined, { headers: { 'x-mdrn-user-id': id, 'x-mdrn-identity-token': 't' } });
    assert.equal(response.status, 401, id);
  }
});

test('a cookie-signed-in write must come from the app\'s own origin', async () => {
  const fake = fakeMdrn();
  const web = { id: 'usr_alice', token: fake.signIn('usr_alice') };
  const note = { title: 'hello' };
  // Another app on the same apps.mdrn.io site, and a request with no Origin at all.
  assert.equal((await call(fake, 'POST', '/api/notes', note, { web, origin: 'https://evil.apps.mdrn.io' })).status, 403);
  assert.equal((await call(fake, 'POST', '/api/notes', note, { web, origin: null })).status, 403);
  assert.equal((await call(fake, 'POST', '/api/notes', note, { web, origin: ORIGIN })).status, 201);
  // Without Origin, the browser's own Sec-Fetch-Site still proves a same-origin request.
  assert.equal((await call(fake, 'POST', '/api/notes', note, { web, origin: null, headers: { 'Sec-Fetch-Site': 'same-origin' } })).status, 201);
});

test('a bearer token is judged alone: Proxy headers next to a bad one do not help', async () => {
  const fake = fakeMdrn(mobileOn);
  const response = await call(fake, 'GET', '/api/me', undefined, { web: { id: 'usr_alice', token: fake.signIn('usr_alice') }, bearer: 'not-a-token' });
  assert.equal(response.status, 401);
  assert.equal(response.headers.get('WWW-Authenticate'), 'Bearer');
});

test('a valid access token signs the mobile user in', async () => {
  const fake = fakeMdrn(mobileOn);
  const token = await issueAccessToken(SECRET, 'usr_bob', 'rec_1');
  const response = await call(fake, 'GET', '/api/me', undefined, { bearer: token });
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { id: 'usr_bob', via: 'mobile' });
});

test('an altered, expired or foreign-signed access token is refused', async () => {
  const fake = fakeMdrn(mobileOn);
  const good = await issueAccessToken(SECRET, 'usr_bob', 'rec_1');
  const [prefix, claims, signature] = good.split('.');
  const forgedClaims = Buffer.from(JSON.stringify({ sub: 'usr_alice', sid: 'rec_1', iat: 0, exp: 4102444800 })).toString('base64url');
  const tokens = [
    `${prefix}.${forgedClaims}.${signature}`,
    `${prefix}.${claims}.${signature.slice(0, -2)}AA`,
    await issueAccessToken(SECRET, 'usr_bob', 'rec_1', Math.floor(Date.now() / 1000) - 3600),
    await issueAccessToken('another-secret-of-thirty-two-characters!', 'usr_bob', 'rec_1'),
  ];
  for (const token of tokens) assert.equal((await call(fake, 'GET', '/api/me', undefined, { bearer: token })).status, 401, token);
});

test('with the mobile module off, bearer tokens and /mobile routes do not exist', async () => {
  const fake = fakeMdrn();
  const token = await issueAccessToken(SECRET, 'usr_bob', 'rec_1');
  assert.equal((await call(fake, 'GET', '/api/me', undefined, { bearer: token })).status, 401);
  assert.equal((await call(fake, 'POST', '/mobile/token', { grant_type: 'refresh_token', refresh_token: 'x' })).status, 404);
});
