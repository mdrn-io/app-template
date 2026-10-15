// The backend: one Hono app, deployed by MDRN as a Worker. Every request reaches it through
// MDRN's Proxy, which has already served sign-in (/login and MDRN's own /_mdrn and /v1/auth
// paths never reach this code) and added the signed-in user's headers (see src/auth.ts).
//
//   GET    /health                      readiness, no sign-in
//   GET    /api/me                      who is signed in
//   *      /api/notes[/:id]             the user's own notes (src/routes/notes.ts)
//   *      /api/files[/:id/...]         the user's own files (src/routes/files.ts)
//   POST   /api/mail/me                 mail the user's own address (src/routes/mail.ts)
//   *      /mobile/...                  optional native-app sign-in (src/mobile/routes.ts)
import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { requireUser } from './auth.ts';
import type { AppEnv } from './env.ts';
import { fail, handleError } from './errors.ts';
import { mobile } from './mobile/routes.ts';
import { rateLimit } from './rate-limit.ts';
import { files } from './routes/files.ts';
import { mail } from './routes/mail.ts';
import { notes } from './routes/notes.ts';

const app = new Hono<AppEnv>();

app.onError(handleError);
app.notFound(c => fail(c, 404, 'not_found', 'Not found.'));

// Readiness: MDRN calls it before a release takes traffic (mdrn.jsonc: readinessPath). It calls no
// product, so it stays cheap and does not fail when a product is briefly unavailable.
app.get('/health', c => c.json({ ok: true }));

// Small bodies only: file bytes go straight to MDRN Files, never through here.
const limitBody = bodyLimit({ maxSize: 64 * 1024, onError: c => fail(c, 413, 'too_large', 'The request body is too large.') });
app.use('/api/*', limitBody);
app.use('/mobile/*', limitBody);

// Everything under /api needs a signed-in user: a browser with MDRN's sign-in cookie, or a
// native app with a bearer token from /mobile/token.
app.use('/api/*', requireUser('any'), rateLimit('api', 120, 60_000, 'user'));
app.use('/api/*', async (c, next) => {
  await next();
  // Answers are per user: never cached by a browser or anything between.
  c.header('Cache-Control', 'private, no-store');
});

app.get('/api/me', c => {
  const user = c.get('user');
  return c.json({ id: user.id, via: user.via });
});
app.route('/api/notes', notes);
app.route('/api/files', files);
app.route('/api/mail', mail);
app.route('/mobile', mobile);

export default app;
