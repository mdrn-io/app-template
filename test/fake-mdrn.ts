// An in-memory stand-in for what MDRN gives a release: the MDRN_PRODUCTS binding with SQLite
// records, Objects and Mail behind it, plus Identity's /v1/auth/me. It follows the real contracts
// closely enough for these tests: required Idempotency-Key on writes, If-Match versions,
// cursors, one-time grants. It is not MDRN; the real thing is exercised by deploying.
import app from '../src/index.ts';
import type { Env } from '../src/env.ts';

export const ORIGIN = 'https://notes.example.apps.mdrn.io';
const TOKENS = { SQLITE: 'mdrn_product_sqlite', OBJECTS: 'mdrn_product_objects', MAIL: 'mdrn_product_mail' };

interface StoredRecord {
  id: string;
  collection: string;
  version: number;
  data: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const error = (status: number, code: string) => json({ error: { code, message: code } }, status);

export function fakeMdrn(settings: Partial<Env> = {}) {
  let sequence = 0;
  const next = (prefix: string) => `${prefix}_${String(++sequence).padStart(6, '0')}`;
  const collections = new Map<string, Map<string, StoredRecord>>();
  const replies = new Map<string, Response>();
  const uploads = new Map<string, { objectId: string; bytes: number; etag?: string; sha256: string; open?: boolean }>();
  const objects = new Map<string, { state: string }>();
  const grants = new Map<string, { uploadId: string; bytes: number }>();
  /** Identity: identity token -> the user's account. */
  const accounts = new Map<string, { id: string; email?: string }>();
  const sent: { recipient: string; subject: string; text: string }[] = [];

  const collection = (name: string) => {
    let records = collections.get(name);
    if (!records) collections.set(name, (records = new Map()));
    return records;
  };

  async function sqlite(request: Request, path: string[]) {
    const [, name, , id] = path; // collections/<name>/records[/<id>]
    const records = collection(name);
    const ifMatch = request.headers.get('If-Match');
    if (request.method === 'GET' && id === undefined) {
      const url = new URL(request.url);
      const limit = Number(url.searchParams.get('limit') ?? 50);
      const after = url.searchParams.get('cursor') ?? '';
      const sorted = [...records.values()].sort((a, b) => a.id.localeCompare(b.id)).filter(r => r.id > after);
      const items = sorted.slice(0, limit);
      return json({ items, nextCursor: sorted.length > limit ? items.at(-1)!.id : null });
    }
    if (request.method === 'GET') {
      const record = records.get(id);
      return record ? json(record) : error(404, 'NOT_FOUND');
    }
    const body: any = request.method === 'DELETE' ? undefined : await request.json();
    if (request.method === 'POST') {
      const now = new Date().toISOString();
      const record = { id: next('rec'), collection: name, version: 1, data: body.data, createdAt: now, updatedAt: now };
      records.set(record.id, record);
      return json(record, 201);
    }
    const record = records.get(id);
    if (!record) return error(404, 'NOT_FOUND');
    if (Number(ifMatch) !== record.version) return error(409, 'CONFLICT');
    if (request.method === 'DELETE') {
      records.delete(id);
      return json({ deleted: true });
    }
    record.data = { ...record.data, ...body.data };
    record.version += 1;
    record.updatedAt = new Date().toISOString();
    return json(record);
  }

  async function objectsApi(request: Request, path: string[]) {
    const body: any = request.method === 'POST' ? await request.json() : undefined;
    if (path[0] === 'uploads' && path.length === 1) {
      const id = next('upl');
      const objectId = next('obj');
      uploads.set(id, { objectId, bytes: body.bytes, sha256: body.sha256 });
      // As Objects does, a new upload opens for parts a moment later: a part asked for before is 409.
      return json({ id, objectId, state: 'pending', expiresAt: '2030-01-01T00:00:00Z', partBytes: 16 * 1024 * 1024 }, 201);
    }
    if (path[0] === 'uploads' && path.length === 2 && request.method === 'GET') {
      const upload = uploads.get(path[1]);
      if (!upload) return error(404, 'NOT_FOUND');
      upload.open = true;
      return json({ id: path[1], objectId: upload.objectId, state: 'uploading', expiresAt: '2030-01-01T00:00:00Z', partBytes: 16 * 1024 * 1024 });
    }
    if (path[0] === 'uploads' && path[2] === 'parts') {
      const upload = uploads.get(path[1]);
      if (upload && !upload.open) return error(409, 'UPLOAD_NOT_READY');
      if (!upload || body.partNumber !== 1 || body.bytes !== upload.bytes) return error(400, 'INVALID_REQUEST');
      const id = next('grant');
      grants.set(id, { uploadId: path[1], bytes: body.bytes });
      return json({ id, url: `https://files.example/transfer/${id}`, method: 'PUT', headers: {}, expiresAt: '2030-01-01T00:00:00Z', maxBytes: body.bytes }, 202);
    }
    if (path[0] === 'uploads' && path[2] === 'complete') {
      const upload = uploads.get(path[1]);
      if (!upload || body.parts.length !== 1 || body.parts[0].etag !== upload.etag) return error(409, 'CONFLICT');
      objects.set(upload.objectId, { state: 'ready' });
      return json({ id: upload.objectId, state: 'verifying' }, 202);
    }
    // /v1/objects/{id}: uploads and operations are matched first, so any other segment is an object id.
    if (path[0] !== 'uploads' && path[1] === 'download-grants') {
      if (objects.get(path[0])?.state !== 'ready') return error(404, 'NOT_FOUND');
      return json({ id: next('grant'), url: `https://files.example/transfer/${next('dl')}`, method: 'GET', headers: {}, expiresAt: '2030-01-01T00:00:00Z', maxBytes: 1 });
    }
    if (path[0] !== 'uploads' && path.length === 1 && request.method === 'DELETE') {
      objects.delete(path[0]);
      return new Response(null, { status: 204 });
    }
    return error(404, 'NOT_FOUND');
  }

  const binding = {
    async fetch(request: Request): Promise<Response> {
      const url = new URL(request.url);
      if (url.origin !== ORIGIN) throw new Error(`unexpected origin ${url.origin}`);
      // Proxy refuses a product call that carries a cookie.
      if (request.headers.has('Cookie')) return error(401, 'PRODUCT_ACCESS_DENIED');
      if (url.pathname === '/v1/auth/me' && request.method === 'GET') {
        const token = request.headers.get('Authorization')?.replace(/^Bearer /, '') ?? '';
        const account = accounts.get(token);
        return account ? json({ id: account.id, email: account.email ?? null }) : error(401, 'invalid_session');
      }
      const product = url.pathname.startsWith('/_mdrn/v1/sqlite/') ? 'SQLITE' : url.pathname === '/v1/objects' || url.pathname.startsWith('/v1/objects/') ? 'OBJECTS' : url.pathname === '/v1/mail/messages' ? 'MAIL' : null;
      if (!product) return error(404, 'NOT_FOUND');
      if (request.headers.get('Authorization') !== `Bearer ${TOKENS[product]}`) return error(401, 'PRODUCT_ACCESS_DENIED');
      const key = request.headers.get('Idempotency-Key');
      if (request.method !== 'GET') {
        if (!key || !/^[A-Za-z0-9_-]{1,128}$/.test(key)) return error(400, 'INVALID_REQUEST');
        const replay = replies.get(`${product}:${key}`);
        if (replay) return replay.clone();
      }
      const path = url.pathname.split('/').filter(Boolean).slice(product === 'SQLITE' ? 3 : 2);
      let response: Response;
      if (product === 'SQLITE') response = await sqlite(request, path);
      else if (product === 'OBJECTS') response = await objectsApi(request, path);
      else {
        const message: any = await request.json();
        sent.push({ recipient: message.recipient, subject: message.subject, text: message.text });
        response = json({ id: next('msg'), state: 'accepted' }, 202);
      }
      if (key && request.method !== 'GET') replies.set(`${product}:${key}`, response.clone());
      return response;
    },
  };

  const env: Env = {
    MDRN_PRODUCTS: binding,
    MDRN_PROJECT_ID: 'prj_test',
    MDRN_ENVIRONMENT: 'sandbox',
    MDRN_SQLITE_URL: `${ORIGIN}/_mdrn/v1/sqlite`,
    MDRN_SQLITE_TOKEN: TOKENS.SQLITE,
    MDRN_OBJECTS_URL: `${ORIGIN}/v1/objects`,
    MDRN_OBJECTS_TOKEN: TOKENS.OBJECTS,
    MDRN_MAIL_URL: `${ORIGIN}/v1/mail`,
    MDRN_MAIL_TOKEN: TOKENS.MAIL,
    ...settings,
  };

  return {
    env,
    collections,
    sent,
    /** Signs a user in to Identity; answers the identity token Proxy would pass on. */
    signIn(id: string, email?: string) {
      const token = `idt_${id}_${++sequence}`;
      accounts.set(token, { id, email });
      return token;
    },
    /** The client's PUT of the bytes to an upload grant URL; answers the etag the transfer gateway returns. */
    upload(grantUrl: string, bytes: number) {
      const grant = grants.get(grantUrl.split('/').at(-1)!);
      if (!grant || grant.bytes !== bytes) throw new Error('grant refused the bytes');
      const etag = `etag_${++sequence}`;
      uploads.get(grant.uploadId)!.etag = etag;
      return etag;
    },
  };
}

export type Fake = ReturnType<typeof fakeMdrn>;

export interface Caller {
  /** A browser signed in through MDRN: Proxy's headers, and this app's own Origin on writes. */
  web?: { id: string; token: string };
  bearer?: string;
  origin?: string | null;
  headers?: Record<string, string>;
}

/** Sends a request to the app the way Proxy would deliver it. */
export async function call(fake: Fake, method: string, path: string, body?: unknown, who: Caller = {}) {
  const headers = new Headers(who.headers);
  if (who.web) {
    headers.set('x-mdrn-user-id', who.web.id);
    headers.set('x-mdrn-identity-token', who.web.token);
  }
  if (who.bearer) headers.set('Authorization', `Bearer ${who.bearer}`);
  const origin = who.origin === undefined ? (who.web && method !== 'GET' ? ORIGIN : null) : who.origin;
  if (origin) headers.set('Origin', origin);
  let payload: BodyInit | undefined;
  if (body instanceof URLSearchParams) payload = body;
  else if (body !== undefined) {
    headers.set('Content-Type', 'application/json');
    payload = JSON.stringify(body);
  }
  const response = await app.fetch(new Request(ORIGIN + path, { method, headers, body: payload, redirect: 'manual' }), fake.env);
  const text = await response.text();
  let parsed: any = text;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {}
  return { status: response.status, headers: response.headers, body: parsed };
}
