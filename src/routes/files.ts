// Files: each user uploads and downloads their own files through MDRN Files grant links.
//
// The bytes never pass through this Worker (which would cost CPU time and memory). Instead:
//   1. POST /api/files            the client says what it will upload; this route checks the
//                                 size and type caps and answers a one-time upload URL.
//   2. PUT <upload.url>           the client sends the bytes straight to MDRN Files. The
//                                 response carries an etag.
//   3. POST /api/files/:id/complete  with that etag. Files checks the bytes against the SHA-256
//                                 the client declared in step 1, then the file is ready.
//   4. GET /api/files/:id/download   answers a short-lived download URL.
// The caps are enforced by Files too: an upload grant accepts exactly the declared byte count.
import { Hono } from 'hono';
import { z } from 'zod';
import { userKey } from '../crypto.ts';
import type { AppEnv, Env } from '../env.ts';
import { fail } from '../errors.ts';
import { db, files as storage, ProductError, type StoredRecord } from '../mdrn.ts';
import { body, idParam, params, query, version } from '../validate.ts';

/** Change these to suit your app. One part holds up to 16 MiB, which keeps this flow to a
 * single PUT; larger files need a multipart upload (see the MDRN Files docs). */
export const MAX_FILE_BYTES = 10 * 1024 * 1024;
export const ALLOWED_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp', 'application/pdf', 'text/plain']);

interface FileRecord {
  ownerId: string;
  uploadId: string;
  objectId: string;
  filename: string;
  contentType: string;
  bytes: number;
  state: 'uploading' | 'complete';
}

const collection = async (userId: string) => `files_${await userKey(userId)}`;

const view = (record: StoredRecord<FileRecord>) => ({
  id: record.id,
  version: record.version,
  filename: record.data.filename,
  contentType: record.data.contentType,
  bytes: record.data.bytes,
  state: record.data.state,
  createdAt: record.createdAt,
});

async function ownFile(env: Env, userId: string, id: string) {
  const record = await db.get<FileRecord>(env, await collection(userId), id);
  return record && record.data.ownerId === userId ? record : null;
}

export const files = new Hono<AppEnv>();

files.get('/', query(z.strictObject({ cursor: z.string().max(2048).optional() })), async c => {
  const user = c.get('user');
  const page = await db.list<FileRecord>(c.env, await collection(user.id), { limit: 50, cursor: c.req.valid('query').cursor });
  return c.json({ items: page.items.filter(r => r.data.ownerId === user.id).map(view), nextCursor: page.nextCursor });
});

files.post(
  '/',
  body(
    z.strictObject({
      // No path separators or control characters: the name is shown back to the user, never
      // used as a path.
      filename: z.string().trim().min(1).max(255).regex(/^[^/\\\p{Cc}]+$/u, 'must be a plain file name'),
      contentType: z.string().refine(type => ALLOWED_TYPES.has(type), 'this file type is not accepted'),
      bytes: z.number().int().min(1).max(MAX_FILE_BYTES, `files can be at most ${MAX_FILE_BYTES} bytes`),
      sha256: z.string().regex(/^[0-9a-f]{64}$/, 'must be the hex SHA-256 of the file'),
    }),
  ),
  async c => {
    const user = c.get('user');
    const input = c.req.valid('json');
    const upload = await storage.createUpload(c.env, input);
    const grant = await storage.createPartGrant(c.env, upload.id, { partNumber: 1, bytes: input.bytes });
    const record = await db.create<FileRecord>(c.env, await collection(user.id), {
      ownerId: user.id,
      uploadId: upload.id,
      objectId: upload.objectId,
      filename: input.filename,
      contentType: input.contentType,
      bytes: input.bytes,
      state: 'uploading',
    });
    return c.json({ file: view(record), upload: { url: grant.url, method: grant.method, headers: grant.headers, expiresAt: grant.expiresAt } }, 201);
  },
);

files.post('/:id/complete', params(idParam), body(z.strictObject({ etag: z.string().min(1).max(256) })), async c => {
  const user = c.get('user');
  const { id } = c.req.valid('param');
  const record = await ownFile(c.env, user.id, id);
  if (!record) return fail(c, 404, 'not_found', 'File not found.');
  if (record.data.state !== 'uploading') return c.json(view(record));
  try {
    await storage.completeUpload(c.env, record.data.uploadId, [{ partNumber: 1, etag: c.req.valid('json').etag }]);
  } catch (error) {
    // The bytes were not all sent, or not as declared.
    if (error instanceof ProductError && (error.status === 400 || error.status === 409)) {
      return fail(c, 409, 'conflict', 'The upload is not complete. Send the file again.');
    }
    throw error;
  }
  const updated = await db.update<FileRecord>(c.env, await collection(user.id), id, { state: 'complete' }, record.version);
  return c.json(view(updated));
});

files.get('/:id/download', params(idParam), async c => {
  const record = await ownFile(c.env, c.get('user').id, c.req.valid('param').id);
  if (!record || record.data.state !== 'complete') return fail(c, 404, 'not_found', 'File not found.');
  try {
    const grant = await storage.createDownloadGrant(c.env, record.data.objectId);
    return c.json({ url: grant.url, expiresAt: grant.expiresAt });
  } catch (error) {
    // Files is still checking the bytes against their SHA-256; that takes moments.
    if (error instanceof ProductError && error.status === 404) return fail(c, 409, 'conflict', 'The file is still being processed. Try again in a moment.');
    throw error;
  }
});

files.delete('/:id', params(idParam), query(z.strictObject({ version: z.coerce.number().pipe(version) })), async c => {
  const user = c.get('user');
  const { id } = c.req.valid('param');
  const record = await ownFile(c.env, user.id, id);
  if (!record) return fail(c, 404, 'not_found', 'File not found.');
  if (record.data.state === 'complete') {
    try {
      await storage.deleteObject(c.env, record.data.objectId);
    } catch (error) {
      // Already gone, or never finished verifying: nothing left to delete.
      if (!(error instanceof ProductError && (error.status === 404 || error.status === 409))) throw error;
    }
  }
  await db.remove(c.env, await collection(user.id), id, c.req.valid('query').version);
  return c.body(null, 204);
});
