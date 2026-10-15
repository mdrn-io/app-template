// Files: grant links for the user's own files, within the size and type caps.
import { beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_FILE_BYTES } from '../src/routes/files.ts';
import { resetRateLimits } from '../src/rate-limit.ts';
import { call, fakeMdrn } from './fake-mdrn.ts';

beforeEach(() => resetRateLimits());

const sha256 = 'a'.repeat(64);
const photo = { filename: 'cat.png', contentType: 'image/png', bytes: 1234, sha256 };

function setup() {
  const fake = fakeMdrn();
  return { fake, alice: { web: { id: 'usr_alice', token: fake.signIn('usr_alice') } }, bob: { web: { id: 'usr_bob', token: fake.signIn('usr_bob') } } };
}

test('upload through a grant, complete, then download through a grant', async () => {
  const { fake, alice } = setup();
  const started = await call(fake, 'POST', '/api/files', photo, alice);
  assert.equal(started.status, 201);
  assert.equal(started.body.file.state, 'uploading');
  assert.equal(started.body.upload.method, 'PUT');
  assert.match(started.body.upload.url, /^https:\/\/files\.example\/transfer\//);

  // Not downloadable before it is complete.
  assert.equal((await call(fake, 'GET', `/api/files/${started.body.file.id}/download`, undefined, alice)).status, 404);

  const etag = fake.upload(started.body.upload.url, photo.bytes);
  const wrong = await call(fake, 'POST', `/api/files/${started.body.file.id}/complete`, { etag: 'not-the-etag' }, alice);
  assert.equal(wrong.status, 409);
  const done = await call(fake, 'POST', `/api/files/${started.body.file.id}/complete`, { etag }, alice);
  assert.equal(done.status, 200);
  assert.equal(done.body.state, 'complete');

  const download = await call(fake, 'GET', `/api/files/${started.body.file.id}/download`, undefined, alice);
  assert.equal(download.status, 200);
  assert.match(download.body.url, /^https:\/\/files\.example\/transfer\//);

  const list = await call(fake, 'GET', '/api/files', undefined, alice);
  assert.deepEqual(list.body.items.map((f: any) => f.filename), ['cat.png']);
  assert.equal((await call(fake, 'DELETE', `/api/files/${started.body.file.id}?version=2`, undefined, alice)).status, 204);
});

test('size and type caps are enforced before Files is asked', async () => {
  const { fake, alice } = setup();
  const refused = [
    { ...photo, bytes: MAX_FILE_BYTES + 1 },
    { ...photo, bytes: 0 },
    { ...photo, contentType: 'text/html' },
    { ...photo, contentType: 'application/x-msdownload' },
    { ...photo, filename: '../../etc/passwd' },
    { ...photo, filename: 'a\nb.png' },
    { ...photo, sha256: 'nope' },
  ];
  for (const body of refused) assert.equal((await call(fake, 'POST', '/api/files', body, alice)).status, 400, JSON.stringify(body));
  assert.equal(fake.collections.size, 0);
});

test('another user can neither complete, download nor delete someone\'s file', async () => {
  const { fake, alice, bob } = setup();
  const started = await call(fake, 'POST', '/api/files', photo, alice);
  const id = started.body.file.id;
  const etag = fake.upload(started.body.upload.url, photo.bytes);
  assert.equal((await call(fake, 'POST', `/api/files/${id}/complete`, { etag }, bob)).status, 404);
  await call(fake, 'POST', `/api/files/${id}/complete`, { etag }, alice);
  assert.equal((await call(fake, 'GET', `/api/files/${id}/download`, undefined, bob)).status, 404);
  assert.equal((await call(fake, 'DELETE', `/api/files/${id}?version=2`, undefined, bob)).status, 404);
  assert.deepEqual((await call(fake, 'GET', '/api/files', undefined, bob)).body.items, []);
  assert.equal((await call(fake, 'GET', `/api/files/${id}/download`, undefined, alice)).status, 200);
});
