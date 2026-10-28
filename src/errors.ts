// One error shape for every client, in this app's own words. What a product said goes to your
// logs (MDRN Logs collects console output), never to the caller: it can name internals.
import type { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { ProductError, ProductUnavailable } from './mdrn.ts';

export type ErrorCode =
  | 'invalid_request'
  | 'invalid_grant'
  | 'unauthenticated'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'too_large'
  | 'rate_limited'
  | 'unavailable';

export function fail(c: Context, status: 400 | 401 | 403 | 404 | 409 | 413 | 415 | 429 | 503, code: ErrorCode, message: string) {
  c.header('Cache-Control', 'no-store');
  return c.json({ error: { code, message } }, status);
}

/** The app's onError handler: anything a route did not answer itself. */
export function handleError(error: Error, c: Context) {
  if (error instanceof HTTPException) {
    // Raised by Hono itself: a body that is not JSON, or one over the size limit.
    if (error.status === 413) return fail(c, 413, 'too_large', 'The request body is too large.');
    if (error.status === 400 || error.status === 415) return fail(c, 400, 'invalid_request', 'The request body must be JSON.');
  }
  if (error instanceof ProductError) {
    // A record changed since the client read it (MDRN's CONFLICT): the client should read it
    // again. Any other 409 is not the client's edit and is answered as MDRN being unavailable.
    if (error.status === 409 && error.code === 'CONFLICT') return fail(c, 409, 'conflict', 'This item changed since you read it. Load it again and retry.');
    if (error.status === 404) return fail(c, 404, 'not_found', 'Not found.');
    if (error.status === 429) return fail(c, 429, 'rate_limited', 'Too many requests. Try again shortly.');
    console.error(JSON.stringify({ event: 'product_error', status: error.status, code: error.code, message: error.message }));
    return fail(c, 503, 'unavailable', 'The service is unavailable right now. Try again shortly.');
  }
  if (error instanceof ProductUnavailable) {
    console.error(JSON.stringify({ event: 'product_unavailable', message: error.message }));
    return fail(c, 503, 'unavailable', 'This feature is not available right now.');
  }
  console.error(JSON.stringify({ event: 'unhandled_error', name: error.name, message: error.message }));
  return fail(c, 503, 'unavailable', 'Something went wrong. Try again shortly.');
}
