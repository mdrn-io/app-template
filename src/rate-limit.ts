// A cheap, best-effort rate limiter: a fixed window counted in this Worker instance's memory.
// It costs nothing per request, but each instance (and each location) counts on its own and
// forgets on restart, so it slows a noisy client down rather than enforcing an exact quota.
// Where a limit must hold exactly, count in SQLite instead, as src/routes/mail.ts does.
// It is advisory: a client that rotates addresses gets fresh windows (and at 10,000 keys the
// oldest are dropped), so nothing that matters may rest on it. /mobile/token's real protection
// is the one-use code and its PKCE verifier; this only keeps a noisy client from costing you.
import type { Context } from 'hono';
import { createMiddleware } from 'hono/factory';
import type { AppEnv } from './env.ts';
import { fail } from './errors.ts';

const windows = new Map<string, { start: number; count: number }>();
const MAX_KEYS = 10_000;

/** True while `key` has made fewer than `max` calls in the current `windowMs`. */
export function allow(key: string, max: number, windowMs: number, at = Date.now()): boolean {
  const current = windows.get(key);
  if (!current || at - current.start >= windowMs) {
    // Bounded memory: drop the oldest entries rather than grow without limit.
    if (windows.size >= MAX_KEYS) windows.delete(windows.keys().next().value!);
    windows.set(key, { start: at, count: 1 });
    return true;
  }
  current.count += 1;
  return current.count <= max;
}

/** For tests. */
export const resetRateLimits = () => windows.clear();

/** The caller's address as MDRN's edge saw it, or undefined. Proxy passes it through to this
 * Worker. */
export const clientAddress = (c: Context): string | undefined => c.req.header('CF-Connecting-IP') || undefined;

/** Limits by signed-in user (after requireUser) or by address (before it). A caller whose user
 * or address is unknown is not limited: one shared bucket would let one client lock out all. */
export const rateLimit = (name: string, max: number, windowMs: number, by: 'user' | 'address') =>
  createMiddleware<AppEnv>(async (c, next) => {
    const who = by === 'user' ? c.get('user')?.id : clientAddress(c);
    if (who !== undefined && !allow(`${name}:${who}`, max, windowMs)) {
      c.header('Retry-After', String(Math.ceil(windowMs / 1000)));
      return fail(c, 429, 'rate_limited', 'Too many requests. Try again shortly.');
    }
    await next();
  });
