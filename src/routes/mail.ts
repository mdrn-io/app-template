// Mail: the signed-in user sends a message to their own address, and only to it.
//
// The request has no recipient field, and one sent anyway is refused: the address always comes
// from MDRN Identity, never from the client. A backend that mails any address a client names is
// a spam relay with your domain's name on it. Sends are also capped per user per day, counted in
// SQLite so the cap holds across every Worker instance.
import { Hono } from 'hono';
import { z } from 'zod';
import { identityEmail } from '../auth.ts';
import { userKey } from '../crypto.ts';
import type { AppEnv, Env, SignedInUser } from '../env.ts';
import { fail } from '../errors.ts';
import { sqlite, mail as mailer, ProductError } from '../mdrn.ts';
import { sessionRecord } from '../mobile/sessions.ts';
import { body } from '../validate.ts';

const DEFAULT_DAILY_LIMIT = 5;

interface Quota {
  day: string;
  count: number;
}

/** The user's own address: from MDRN Identity for web, from the mobile session for mobile (it
 * was read from Identity when that session signed in). */
async function ownAddress(env: Env, requestUrl: string, user: SignedInUser): Promise<string | null> {
  if (user.via === 'web') return user.identityToken ? identityEmail(env, requestUrl, user.identityToken) : null;
  const session = user.sessionId ? await sessionRecord(env, user.id, user.sessionId) : null;
  // A signed-out session stops here at once, even while its access token has minutes left.
  if (!session || session.data.revokedAt) return null;
  return session.data.email;
}

/** Counts one send against today's cap; false when the cap is reached. */
async function takeQuota(env: Env, userId: string, limit: number): Promise<boolean> {
  const collection = `mail_quota_${await userKey(userId)}`;
  const today = new Date().toISOString().slice(0, 10);
  for (let attempt = 0; attempt < 3; attempt++) {
    const [current] = (await sqlite.list<Quota>(env, collection, { limit: 1 })).items;
    if (!current) {
      await sqlite.create<Quota>(env, collection, { day: today, count: 1 });
      return true;
    }
    const used = current.data.day === today ? current.data.count : 0;
    if (used >= limit) return false;
    try {
      await sqlite.update<Quota>(env, collection, current.id, { day: today, count: used + 1 }, current.version);
      return true;
    } catch (error) {
      // Another send counted at the same moment: read the count again.
      if (!(error instanceof ProductError && error.status === 409)) throw error;
    }
  }
  return false;
}

export const mail = new Hono<AppEnv>();

mail.post(
  '/me',
  // strictObject: a body with `recipient`, `to`, `cc` or anything else unexpected is refused.
  body(
    z.strictObject({
      subject: z.string().trim().min(1).max(200).regex(/^[^\p{Cc}]+$/u, 'must be one line'),
      text: z.string().trim().min(1).max(5_000),
    }),
  ),
  async c => {
    const user = c.get('user');
    const recipient = await ownAddress(c.env, c.req.url, user);
    if (!recipient) return fail(c, 409, 'conflict', 'Your account has no email address to send to.');
    const parsedLimit = Number.parseInt(c.env.MAIL_DAILY_LIMIT ?? '', 10);
    const limit = Number.isSafeInteger(parsedLimit) && parsedLimit >= 0 ? parsedLimit : DEFAULT_DAILY_LIMIT;
    if (!(await takeQuota(c.env, user.id, limit))) return fail(c, 429, 'rate_limited', 'You have sent the most messages allowed today.');
    const { subject, text } = c.req.valid('json');
    await mailer.send(c.env, { recipient, subject, text });
    return c.json({ sent: true }, 202);
  },
);
