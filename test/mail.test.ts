// Mail goes only to the signed-in user's own address, as MDRN Identity knows it.
import { beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { resetRateLimits } from '../src/rate-limit.ts';
import { call, fakeMdrn } from './fake-mdrn.ts';

beforeEach(() => resetRateLimits());

const message = { subject: 'Your notes', text: 'Here they are.' };

test('a message goes to the address Identity has for the signed-in user', async () => {
  const fake = fakeMdrn();
  const alice = { web: { id: 'usr_alice', token: fake.signIn('usr_alice', 'alice@example.com') } };
  const response = await call(fake, 'POST', '/api/mail/me', message, alice);
  assert.equal(response.status, 202);
  assert.deepEqual(fake.sent, [{ recipient: 'alice@example.com', ...message }]);
});

test('a client cannot choose the recipient', async () => {
  const fake = fakeMdrn();
  const alice = { web: { id: 'usr_alice', token: fake.signIn('usr_alice', 'alice@example.com') } };
  for (const extra of [{ recipient: 'victim@example.com' }, { to: 'victim@example.com' }, { cc: 'victim@example.com' }, { bcc: ['a@b.c'] }, { email: 'victim@example.com' }]) {
    const response = await call(fake, 'POST', '/api/mail/me', { ...message, ...extra }, alice);
    assert.equal(response.status, 400, JSON.stringify(extra));
  }
  assert.deepEqual(fake.sent, []);
});

test('a header-like subject and empty text are refused', async () => {
  const fake = fakeMdrn();
  const alice = { web: { id: 'usr_alice', token: fake.signIn('usr_alice', 'alice@example.com') } };
  for (const body of [{ ...message, subject: 'Hi\r\nBcc: victim@example.com' }, { ...message, text: '' }, { ...message, text: 'x'.repeat(5001) }]) {
    assert.equal((await call(fake, 'POST', '/api/mail/me', body, alice)).status, 400);
  }
  assert.deepEqual(fake.sent, []);
});

test('an account without an email address gets nothing sent', async () => {
  const fake = fakeMdrn();
  const response = await call(fake, 'POST', '/api/mail/me', message, { web: { id: 'usr_google', token: fake.signIn('usr_google') } });
  assert.equal(response.status, 409);
  assert.deepEqual(fake.sent, []);
});

test('an identity token Identity does not accept gets nothing sent', async () => {
  const fake = fakeMdrn();
  const response = await call(fake, 'POST', '/api/mail/me', message, { web: { id: 'usr_alice', token: 'forged' } });
  assert.equal(response.status, 409);
  assert.deepEqual(fake.sent, []);
});

test('each user has a daily cap, counted in Database', async () => {
  const fake = fakeMdrn({ MAIL_DAILY_LIMIT: '2' });
  const alice = { web: { id: 'usr_alice', token: fake.signIn('usr_alice', 'alice@example.com') } };
  const bob = { web: { id: 'usr_bob', token: fake.signIn('usr_bob', 'bob@example.com') } };
  assert.equal((await call(fake, 'POST', '/api/mail/me', message, alice)).status, 202);
  assert.equal((await call(fake, 'POST', '/api/mail/me', message, alice)).status, 202);
  // The in-memory limiter forgets on restart; the cap does not.
  resetRateLimits();
  const third = await call(fake, 'POST', '/api/mail/me', message, alice);
  assert.equal(third.status, 429);
  assert.equal((await call(fake, 'POST', '/api/mail/me', message, bob)).status, 202, 'caps are per user');
  assert.equal(fake.sent.length, 3);
});
