// Notes belong to the user who made them, and nobody else can see or change them.
import { beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { userKey } from '../src/crypto.ts';
import { resetRateLimits } from '../src/rate-limit.ts';
import { call, fakeMdrn } from './fake-mdrn.ts';

beforeEach(() => resetRateLimits());

function setup() {
  const fake = fakeMdrn();
  const alice = { web: { id: 'usr_alice', token: fake.signIn('usr_alice') } };
  const bob = { web: { id: 'usr_bob', token: fake.signIn('usr_bob') } };
  return { fake, alice, bob };
}

test('a user creates, lists, reads, updates and deletes their notes', async () => {
  const { fake, alice } = setup();
  const created = await call(fake, 'POST', '/api/notes', { title: 'Groceries', body: 'milk' }, alice);
  assert.equal(created.status, 201);
  assert.equal(created.body.title, 'Groceries');
  assert.equal(created.body.version, 1);
  assert.equal(created.body.ownerId, undefined, 'the owner is not echoed back');

  const list = await call(fake, 'GET', '/api/notes', undefined, alice);
  assert.deepEqual(list.body.items.map((n: any) => n.id), [created.body.id]);

  const read = await call(fake, 'GET', `/api/notes/${created.body.id}`, undefined, alice);
  assert.equal(read.body.body, 'milk');

  const updated = await call(fake, 'PATCH', `/api/notes/${created.body.id}`, { version: 1, body: 'milk, eggs' }, alice);
  assert.equal(updated.status, 200);
  assert.equal(updated.body.version, 2);
  assert.equal(updated.body.title, 'Groceries');

  const removed = await call(fake, 'DELETE', `/api/notes/${created.body.id}?version=2`, undefined, alice);
  assert.equal(removed.status, 204);
  assert.equal((await call(fake, 'GET', `/api/notes/${created.body.id}`, undefined, alice)).status, 404);
});

test('another user cannot list, read, change or delete them', async () => {
  const { fake, alice, bob } = setup();
  const note = (await call(fake, 'POST', '/api/notes', { title: 'Private' }, alice)).body;

  assert.deepEqual((await call(fake, 'GET', '/api/notes', undefined, bob)).body.items, []);
  for (const [method, path, body] of [
    ['GET', `/api/notes/${note.id}`, undefined],
    ['PATCH', `/api/notes/${note.id}`, { version: 1, title: 'Mine now' }],
    ['DELETE', `/api/notes/${note.id}?version=1`, undefined],
  ] as const) {
    const response = await call(fake, method, path, body, bob);
    assert.equal(response.status, 404, `${method} answers as if the note did not exist`);
  }
  const still = await call(fake, 'GET', `/api/notes/${note.id}`, undefined, alice);
  assert.equal(still.body.title, 'Private');
  assert.equal(still.body.version, 1);
});

test('the owner check holds even for a record that is in the wrong collection', async () => {
  // Defence in depth: should a record owned by Alice ever sit in Bob's collection (a bug, a
  // migration, a hand edit), Bob still cannot read it.
  const { fake, alice, bob } = setup();
  const note = (await call(fake, 'POST', '/api/notes', { title: 'Alice only' }, alice)).body;
  const aliceNotes = fake.collections.get(`notes_${await userKey('usr_alice')}`)!;
  const bobNotes = `notes_${await userKey('usr_bob')}`;
  fake.collections.set(bobNotes, new Map([[note.id, { ...aliceNotes.get(note.id)!, collection: bobNotes }]]));

  assert.equal((await call(fake, 'GET', `/api/notes/${note.id}`, undefined, bob)).status, 404);
  assert.deepEqual((await call(fake, 'GET', '/api/notes', undefined, bob)).body.items, []);
  assert.equal((await call(fake, 'PATCH', `/api/notes/${note.id}`, { version: 1, title: 'x' }, bob)).status, 404);
});

test('an update from a stale version is refused, not applied', async () => {
  const { fake, alice } = setup();
  const note = (await call(fake, 'POST', '/api/notes', { title: 'v1' }, alice)).body;
  await call(fake, 'PATCH', `/api/notes/${note.id}`, { version: 1, title: 'v2 from tab A' }, alice);
  const stale = await call(fake, 'PATCH', `/api/notes/${note.id}`, { version: 1, title: 'v2 from tab B' }, alice);
  assert.equal(stale.status, 409);
  assert.equal(stale.body.error.code, 'conflict');
  assert.equal((await call(fake, 'GET', `/api/notes/${note.id}`, undefined, alice)).body.title, 'v2 from tab A');
});

test('input is validated before anything is stored', async () => {
  const { fake, alice } = setup();
  const bad = [
    {},
    { title: '' },
    { title: '   ' },
    { title: 'x'.repeat(201) },
    { title: 'ok', body: 'x'.repeat(10_001) },
    { title: 'ok', ownerId: 'usr_bob' },
    { title: 42 },
  ];
  for (const body of bad) {
    const response = await call(fake, 'POST', '/api/notes', body, alice);
    assert.equal(response.status, 400, JSON.stringify(body));
    assert.equal(response.body.error.code, 'invalid_request');
  }
  assert.equal((await call(fake, 'GET', '/api/notes/bad%20id', undefined, alice)).status, 400);
  assert.equal((await call(fake, 'DELETE', '/api/notes/rec_1', undefined, alice)).status, 400, 'version is required');
  assert.equal((await call(fake, 'GET', '/api/notes?unexpected=1', undefined, alice)).status, 400);
  // A body that is not JSON.
  const response = await call(fake, 'POST', '/api/notes', undefined, { ...alice, headers: { 'Content-Type': 'application/json' } });
  assert.equal(response.status, 400);
  assert.equal(fake.collections.size, 0, 'nothing was stored');
});

test('a body over the size limit is refused', async () => {
  const { fake, alice } = setup();
  const response = await call(fake, 'POST', '/api/notes', { title: 'big', body: 'x'.repeat(70 * 1024) }, alice);
  assert.equal(response.status, 413);
});
