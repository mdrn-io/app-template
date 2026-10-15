// A small client for the MDRN products this template uses: Database records, Files (Storage)
// and Mail. Each call goes through the MDRN_PRODUCTS binding with the product's own token, which
// MDRN injected into this release. The tokens never leave this Worker.
//
// Every write carries an Idempotency-Key: MDRN requires one, and repeating a call with the same
// key returns the first result instead of doing the work twice.
import type { Env } from './env.ts';

/** A product call that did not succeed. `code` is MDRN's error code, such as CONFLICT. The
 * message is MDRN's and is for your logs; answer clients in your own words (see src/errors.ts). */
export class ProductError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ProductError';
    this.status = status;
    this.code = code;
  }
}

/** A product this release has no binding for: it is not turned on for the environment. */
export class ProductUnavailable extends Error {
  constructor(product: string) {
    super(`${product} is not enabled for this environment`);
    this.name = 'ProductUnavailable';
  }
}

type Product = 'DATABASE' | 'STORAGE' | 'MAIL';

interface CallOptions {
  method?: string;
  body?: unknown;
  idempotencyKey?: string;
  ifMatch?: number;
}

// The token is a bearer credential: it only goes to an https URL (plain http only to this
// machine, for local development). MDRN always injects https URLs.
function secureBase(product: Product, base: string) {
  let url: URL;
  try {
    url = new URL(base);
  } catch {
    throw new Error(`MDRN_${product}_URL is not a URL`);
  }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) throw new Error(`MDRN_${product}_URL must be an https URL`);
}

async function call<T>(env: Env, product: Product, path: string, options: CallOptions = {}): Promise<T> {
  const base = env[`MDRN_${product}_URL`];
  const token = env[`MDRN_${product}_TOKEN`];
  if (!env.MDRN_PRODUCTS || !base || !token) throw new ProductUnavailable(product.toLowerCase());
  secureBase(product, base);
  const headers = new Headers({ Accept: 'application/json', Authorization: `Bearer ${token}` });
  if (options.body !== undefined) headers.set('Content-Type', 'application/json');
  if (options.idempotencyKey) headers.set('Idempotency-Key', options.idempotencyKey);
  if (options.ifMatch !== undefined) headers.set('If-Match', String(options.ifMatch));
  const response = await env.MDRN_PRODUCTS.fetch(
    new Request(base + path, {
      method: options.method ?? 'GET',
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
    }),
  );
  // Workers allow only 'follow' or 'manual'. A redirect is never followed, so the token cannot be
  // carried to another origin.
  if (response.status >= 300 && response.status < 400) {
    throw new ProductError(response.status, 'UNEXPECTED_REDIRECT', `MDRN answered with a redirect (HTTP ${response.status}), which is not followed`);
  }
  const payload: any = response.status === 204 ? undefined : await response.json().catch(() => undefined);
  if (!response.ok) {
    // The same reading as @mdrnio/sdk: MDRN's error envelope, a bare {code, message}, or neither.
    const error = payload?.error && typeof payload.error === 'object' ? payload.error : payload;
    throw new ProductError(
      response.status,
      typeof error?.code === 'string' ? error.code : 'HTTP_ERROR',
      typeof error?.message === 'string' ? error.message : `MDRN request failed with HTTP ${response.status}`,
    );
  }
  return payload as T;
}

/** A fresh key for a write that should happen once. */
export const newKey = () => crypto.randomUUID();

// ---------------------------------------------------------------------------------------------
// Database records
//
// A record is a JSON object (up to 64 KiB) in a named collection, with an id MDRN assigns and a
// version that grows by one on every change. Updates and deletes name the version they expect
// (If-Match); if the record changed since, MDRN answers 409 CONFLICT and nothing is written.

export interface StoredRecord<T> {
  id: string;
  collection: string;
  version: number;
  data: T;
  createdAt: string;
  updatedAt: string;
}

export interface RecordPage<T> {
  items: StoredRecord<T>[];
  nextCursor: string | null;
}

const recordsPath = (collection: string, id?: string) =>
  `/collections/${encodeURIComponent(collection)}/records${id === undefined ? '' : `/${encodeURIComponent(id)}`}`;

export const db = {
  create<T>(env: Env, collection: string, data: T, idempotencyKey = newKey()) {
    return call<StoredRecord<T>>(env, 'DATABASE', recordsPath(collection), { method: 'POST', body: { data }, idempotencyKey });
  },
  /** The record, or null when there is none with that id. */
  async get<T>(env: Env, collection: string, id: string): Promise<StoredRecord<T> | null> {
    try {
      return await call<StoredRecord<T>>(env, 'DATABASE', recordsPath(collection, id));
    } catch (error) {
      if (error instanceof ProductError && error.status === 404) return null;
      throw error;
    }
  },
  list<T>(env: Env, collection: string, options: { limit?: number; cursor?: string } = {}) {
    const query = new URLSearchParams();
    if (options.limit) query.set('limit', String(options.limit));
    if (options.cursor) query.set('cursor', options.cursor);
    return call<RecordPage<T>>(env, 'DATABASE', recordsPath(collection) + (query.size ? `?${query}` : ''));
  },
  /** Merges `data` into the record's fields. */
  update<T>(env: Env, collection: string, id: string, data: Partial<T>, version: number, idempotencyKey = newKey()) {
    return call<StoredRecord<T>>(env, 'DATABASE', recordsPath(collection, id), { method: 'PATCH', body: { data }, idempotencyKey, ifMatch: version });
  },
  remove(env: Env, collection: string, id: string, version: number, idempotencyKey = newKey()) {
    return call<{ deleted: true }>(env, 'DATABASE', recordsPath(collection, id), { method: 'DELETE', idempotencyKey, ifMatch: version });
  },
};

// ---------------------------------------------------------------------------------------------
// Files (Storage)
//
// Bytes never pass through this Worker. It asks Files for a grant, a short-lived signed URL, and
// the client sends or fetches the bytes there directly. Files of up to 16 MiB are one part.

export interface Grant {
  id: string;
  url: string;
  method: 'PUT' | 'GET';
  headers: Record<string, string>;
  expiresAt: string;
  maxBytes: number;
}

export interface Upload {
  id: string;
  objectId: string;
  state: string;
  expiresAt: string;
  partBytes: number;
}

export const files = {
  createUpload(env: Env, input: { filename: string; contentType: string; bytes: number; sha256: string }, idempotencyKey = newKey()) {
    return call<Upload>(env, 'STORAGE', '/uploads', { method: 'POST', body: input, idempotencyKey });
  },
  createPartGrant(env: Env, uploadId: string, part: { partNumber: number; bytes: number }, idempotencyKey = newKey()) {
    return call<Grant>(env, 'STORAGE', `/uploads/${encodeURIComponent(uploadId)}/parts`, { method: 'POST', body: part, idempotencyKey });
  },
  completeUpload(env: Env, uploadId: string, parts: { partNumber: number; etag: string }[], idempotencyKey = newKey()) {
    return call<{ id: string; state: string }>(env, 'STORAGE', `/uploads/${encodeURIComponent(uploadId)}/complete`, { method: 'POST', body: { parts }, idempotencyKey });
  },
  createDownloadGrant(env: Env, objectId: string, idempotencyKey = newKey()) {
    return call<Grant>(env, 'STORAGE', `/objects/${encodeURIComponent(objectId)}/download-grants`, { method: 'POST', body: {}, idempotencyKey });
  },
  deleteObject(env: Env, objectId: string, idempotencyKey = newKey()) {
    return call<void>(env, 'STORAGE', `/objects/${encodeURIComponent(objectId)}`, { method: 'DELETE', idempotencyKey });
  },
};

// ---------------------------------------------------------------------------------------------
// Mail
//
// Mail delivers to anyone, from a verified sender, in a Sandbox environment as in Production,
// which is why this template only ever mails the signed-in user's own address.

export const mail = {
  send(env: Env, message: { recipient: string; subject: string; text: string; html?: string | null }, idempotencyKey = newKey()) {
    return call<{ id: string }>(env, 'MAIL', '/messages', { method: 'POST', body: { html: null, ...message }, idempotencyKey });
  },
};
