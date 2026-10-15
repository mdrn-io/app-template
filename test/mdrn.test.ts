// The product client itself: what a failed, redirected or misconfigured call looks like.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { db, ProductError } from '../src/mdrn.ts';
import type { Env } from '../src/env.ts';

const envAnswering = (response: () => Response, url = 'https://notes.example.apps.mdrn.io/_mdrn/v1/database'): Env => ({
  MDRN_PRODUCTS: { fetch: async () => response() },
  MDRN_DATABASE_URL: url,
  MDRN_DATABASE_TOKEN: 'mdrn_product_database',
});

test('a failed call carries MDRN\'s code, or HTTP_ERROR when the body is not an MDRN error', async () => {
  for (const [body, code, message] of [
    [JSON.stringify({ error: { code: 'CONFLICT', message: 'Changed' } }), 'CONFLICT', 'Changed'],
    [JSON.stringify({ code: 'CONFLICT', message: 'Changed' }), 'CONFLICT', 'Changed'],
    [JSON.stringify({ error: 'Not found' }), 'HTTP_ERROR', 'MDRN request failed with HTTP 409'],
    ['Bad gateway', 'HTTP_ERROR', 'MDRN request failed with HTTP 409'],
  ]) {
    const env = envAnswering(() => new Response(body, { status: 409 }));
    await assert.rejects(db.list(env, 'notes'), (error: unknown) => error instanceof ProductError && error.status === 409 && error.code === code && error.message === message);
  }
});

test('a redirect is refused, not followed', async () => {
  let calls = 0;
  const env = envAnswering(() => {
    calls++;
    return new Response(null, { status: 302, headers: { Location: 'https://elsewhere.example/' } });
  });
  await assert.rejects(db.list(env, 'notes'), (error: unknown) => error instanceof ProductError && error.status === 302 && error.code === 'UNEXPECTED_REDIRECT');
  assert.equal(calls, 1);
});

test('the product token only goes to an https URL', async () => {
  let calls = 0;
  const answer = () => {
    calls++;
    return Response.json({ items: [], nextCursor: null });
  };
  await assert.rejects(db.list(envAnswering(answer, 'http://notes.example.apps.mdrn.io/_mdrn/v1/database'), 'notes'), /must be an https URL/);
  assert.equal(calls, 0);
  await db.list(envAnswering(answer, 'http://localhost:8787/_mdrn/v1/database'), 'notes');
  assert.equal(calls, 1);
});
