// Notes: create, list, read, update and delete notes that belong to the signed-in user.
//
// Where they live: each user's notes are a SQLite collection of their own, named from their
// user id (notes_u…). Listing a user's notes therefore reads only their records, however many
// users there are. Every note also records its owner, and every route checks that owner in code
// before it answers, so a note can only ever be read or changed by the user who made it.
import { Hono } from 'hono';
import { z } from 'zod';
import { userKey } from '../crypto.ts';
import type { AppEnv } from '../env.ts';
import { fail } from '../errors.ts';
import { sqlite, type StoredRecord } from '../mdrn.ts';
import { body, idParam, params, query, version } from '../validate.ts';

interface Note {
  ownerId: string;
  title: string;
  body: string;
}

const collection = async (userId: string) => `notes_${await userKey(userId)}`;

/** What a client sees of a note. */
const view = (record: StoredRecord<Note>) => ({
  id: record.id,
  version: record.version,
  title: record.data.title,
  body: record.data.body,
  createdAt: record.createdAt,
  updatedAt: record.updatedAt,
});

const title = z.string().trim().min(1).max(200);
const text = z.string().max(10_000);

export const notes = new Hono<AppEnv>();

/** Reads a note and checks that the signed-in user owns it; null otherwise. A note someone else
 * owns answers exactly like one that does not exist, so ids reveal nothing. */
async function ownNote(env: AppEnv['Bindings'], userId: string, id: string) {
  const record = await sqlite.get<Note>(env, await collection(userId), id);
  return record && record.data.ownerId === userId ? record : null;
}

notes.get('/', query(z.strictObject({ cursor: z.string().max(2048).optional() })), async c => {
  const user = c.get('user');
  const page = await sqlite.list<Note>(c.env, await collection(user.id), { limit: 50, cursor: c.req.valid('query').cursor });
  return c.json({
    items: page.items.filter(record => record.data.ownerId === user.id).map(view),
    nextCursor: page.nextCursor,
  });
});

notes.post('/', body(z.strictObject({ title, body: text.default('') })), async c => {
  const user = c.get('user');
  const input = c.req.valid('json');
  const record = await sqlite.create<Note>(c.env, await collection(user.id), { ownerId: user.id, title: input.title, body: input.body });
  return c.json(view(record), 201);
});

notes.get('/:id', params(idParam), async c => {
  const record = await ownNote(c.env, c.get('user').id, c.req.valid('param').id);
  if (!record) return fail(c, 404, 'not_found', 'Note not found.');
  return c.json(view(record));
});

// The client sends the version it last read. If the note changed since, the update is refused
// with 409 and the client reloads it: no silent overwrite of someone's other tab.
notes.patch(
  '/:id',
  params(idParam),
  body(z.strictObject({ version, title: title.optional(), body: text.optional() }).refine(v => v.title !== undefined || v.body !== undefined, 'nothing to change')),
  async c => {
    const user = c.get('user');
    const { id } = c.req.valid('param');
    const { version: expected, ...changes } = c.req.valid('json');
    const record = await ownNote(c.env, user.id, id);
    if (!record) return fail(c, 404, 'not_found', 'Note not found.');
    const updated = await sqlite.update<Note>(c.env, await collection(user.id), id, changes, expected);
    return c.json(view(updated));
  },
);

notes.delete('/:id', params(idParam), query(z.strictObject({ version: z.coerce.number().pipe(version) })), async c => {
  const user = c.get('user');
  const { id } = c.req.valid('param');
  const record = await ownNote(c.env, user.id, id);
  if (!record) return fail(c, 404, 'not_found', 'Note not found.');
  await sqlite.remove(c.env, await collection(user.id), id, c.req.valid('query').version);
  return c.body(null, 204);
});
