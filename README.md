# MDRN app backend template

A small, readable backend for a web app (React, Vue, Svelte…) or a native app (iOS, Android,
React Native), ready to deploy on [MDRN](https://mdrn.io) without edits. Your frontend never
talks to MDRN's products directly: it calls this backend, and this backend decides what the
signed-in user may do.

It is a TypeScript [Hono](https://hono.dev) app that runs as a Worker, and it shows:

- **Who is calling**: the signed-in user from MDRN's sign-in, with a CSRF check on writes.
- **Notes**: create, list, read, update and delete records that belong to the signed-in user,
  stored in MDRN Database. Ownership is checked in code on every route.
- **Files**: upload and download through MDRN Files grant links, with size and type caps. The
  bytes go straight between the client and Files, never through the Worker.
- **Mail**: send a message to the signed-in user's own address, and only to it, with a daily cap.
- **Mobile sign-in** (optional): MDRN's hosted login in the system browser, then this backend's
  own short-lived access tokens and rotating refresh tokens, with PKCE, reuse detection,
  revocation and logout.
- Input validation on every route, cheap rate limits, and errors in the app's own words.

MIT licensed: copy it, change it, ship it.

```
mdrn.jsonc            how MDRN builds it: entry, tests, readiness path
src/index.ts          the routes, and the middleware in front of them
src/auth.ts           the signed-in user: MDRN's headers, or a mobile bearer token
src/mdrn.ts           a small client for Database, Files and Mail
src/routes/notes.ts   per-user records with ownership checks
src/routes/files.ts   grant-link uploads and downloads
src/routes/mail.ts    mail to the user's own address
src/mobile/           native-app sign-in: PKCE codes, access and refresh tokens
test/                 node --test suites, against an in-memory stand-in for MDRN
```

## Deploy it to MDRN

1. Put this repository on GitHub and connect it to a service in the MDRN console (or upload the
   source). MDRN runs `npm ci`, then `npm test` (from `mdrn.jsonc`), bundles `src/index.ts` and
   waits for `/health` before the release takes traffic.
2. In the environment, turn on the products the routes use: **Database** (notes, files, mobile
   sessions), **Files** and **Mail**. MDRN then injects their `MDRN_*` bindings into every release.
   A route whose product is off answers 503 in plain words; the rest keep working.
3. Turn on **sign-in** for the service's origin, in the console or with
   `mdrn identity enable --origin https://<your app>`. MDRN then serves the hosted `/login` page
   on your app's hostname.

Keep the service's sign-in policy at **mixed** (the default). This backend checks sign-in itself
on `/api/*`, and a native app's calls carry a bearer token instead of the sign-in cookie, so a
policy that requires sign-in for every path would turn them away before they arrive.

Nothing else is required. The mobile module stays off until you configure it (below).

Mail delivers to anyone, from a verified sender, in a **Sandbox** environment as in
Production, which is exactly why this template never lets a client choose the recipient.

## How the signed-in user arrives

MDRN's Proxy sits in front of every request. When sign-in is on and the browser has a session,
Proxy adds two headers before the request reaches this Worker:

| Header | What it is |
| --- | --- |
| `x-mdrn-user-id` | the user's id |
| `x-mdrn-identity-token` | a short-lived token for the session, issued by MDRN Identity |

Proxy first **deletes every `x-mdrn-*` header the caller sent**, so a client cannot forge them,
and this Worker can only be reached through Proxy. `src/auth.ts` therefore trusts them, checks
their shape, and does one more thing for every cookie-signed-in write: the `Origin` must be the
app's own. Every app on `*.apps.mdrn.io` shares that parent domain, and a browser that does not
yet treat it as a public suffix sees them all as one "site", so without that check another app's
page could post here with your user's cookie.

The user's email address is not in the headers. When the mail route needs it, the backend asks
MDRN's `/v1/auth/me` with the identity token, so the address always comes from MDRN.

Locally (`wrangler dev`) there is no Proxy and anyone can send those headers: never expose a
local server.

Each user's records live in collections named after them (`notes_u…`, `files_u…`), so listing
one user's notes reads only theirs. Every record also stores its owner, and every route checks it.

## Call it from a React SPA

Sign-in is per hostname, so serve the SPA from the same hostname as this backend. The simplest
way is to build the SPA into this repository and let the same service serve it, with the API
paths answered by the Worker first. In `mdrn.jsonc`:

```jsonc
"assets": {
  "directory": "public",
  "notFoundHandling": "single-page-application",
  "runWorkerFirst": ["/api/*", "/mobile/*", "/health"]
}
```

Then call it with plain same-origin `fetch`. The browser sends MDRN's sign-in cookie by itself.

```ts
async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...init,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...init.headers },
  });
  if (response.status === 401) {
    location.assign('/login'); // MDRN's hosted sign-in
    throw new Error('signed out');
  }
  if (!response.ok) throw new Error((await response.json()).error.message);
  return response.status === 204 ? (undefined as T) : response.json();
}

const notes = await api<{ items: Note[] }>('/api/notes');
await api('/api/notes', { method: 'POST', body: JSON.stringify({ title: 'Hello' }) });

// Sign out: MDRN's own session endpoint.
const { csrfToken } = await (await fetch('/_mdrn/v1/platform/csrf')).json();
await fetch('/_mdrn/v1/auth/session', { method: 'DELETE', headers: { 'X-CSRF-Token': csrfToken } });
```

Uploading a file: `POST /api/files` with `{ filename, contentType, bytes, sha256 }`, `PUT` the
bytes to the returned `upload.url`, then `POST /api/files/:id/complete` with the `etag` from
that response. `GET /api/files/:id/download` answers a short-lived URL to fetch.

## Native apps (iOS, Android, React Native)

Turn the mobile module on with two service variables (console: the service's Variables):

| Variable | Value |
| --- | --- |
| `MOBILE_TOKEN_SECRET` | at least 32 random characters, marked secret |
| `MOBILE_REDIRECT_URIS` | the exact URIs the app may receive the code at, comma-separated |

Prefer a universal link / App Link (`https://example.com/app/signed-in`) over a custom scheme:
another app can claim a custom scheme, though without your PKCE verifier the code is useless to it.

The flow (OAuth 2.0 authorization code with PKCE):

1. The app makes a random `code_verifier`, its SHA-256 as base64url (`code_challenge`) and a
   random `state`, and opens
   `https://<your app>/mobile/start?redirect_uri=…&code_challenge=…&code_challenge_method=S256&state=…`
   in **ASWebAuthenticationSession** (iOS) or a **Custom Tab** (Android). Never an embedded
   web view.
2. The user signs in on MDRN's hosted page and presses **Continue**. The browser is sent to
   `redirect_uri?code=…&state=…`. The code is one-time and valid for 60 seconds; no token ever
   appears in a URL.
3. The app checks `state` and exchanges the code:
   `POST /mobile/token {"grant_type":"authorization_code","code":…,"code_verifier":…,"redirect_uri":…}`
   → `{ access_token, refresh_token, expires_in }`.
4. API calls send `Authorization: Bearer <access_token>` (valid 10 minutes).
5. When it expires: `POST /mobile/token {"grant_type":"refresh_token","refresh_token":…}`. Each
   refresh token works **once** and comes back replaced; keep only the newest, in the Keychain or
   Keystore, and never run two refreshes at once. Presenting an already-used refresh token ends
   the whole session (that is how a stolen one is caught).
6. Sign out with `POST /mobile/logout` (bearer), or `{"everywhere": true}` for every device.
   `POST /mobile/revoke {"token": <refresh_token>}` ends a session without an access token.

Refresh tokens are stored only as hashes. After a logout the refresh token stops at once; an
access token already issued keeps working until it expires (at most 10 minutes), except where a
route reads the session itself, as the mail route does.

Swift:

```swift
import AuthenticationServices
import CryptoKit

func randomURLSafe(_ count: Int) -> String {
    var bytes = [UInt8](repeating: 0, count: count)
    _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    return Data(bytes).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

let verifier = randomURLSafe(32), state = randomURLSafe(16)
let challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64EncodedString()
    .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "=", with: "")
var start = URLComponents(string: "https://your-app.apps.mdrn.io/mobile/start")!
start.queryItems = [
    .init(name: "redirect_uri", value: "com.example.app:/signed-in"),
    .init(name: "code_challenge", value: challenge),
    .init(name: "code_challenge_method", value: "S256"),
    .init(name: "state", value: state),
]
let session = ASWebAuthenticationSession(url: start.url!, callbackURLScheme: "com.example.app") { url, _ in
    let items = url.flatMap { URLComponents(url: $0, resolvingAgainstBaseURL: false)?.queryItems } ?? []
    guard items.first(where: { $0.name == "state" })?.value == state,
          let code = items.first(where: { $0.name == "code" })?.value else { return }
    // POST /mobile/token with code, verifier and the redirect URI; store the tokens in the Keychain.
}
session.prefersEphemeralWebBrowserSession = true // no lingering browser session
session.presentationContextProvider = self
session.start()
```

React Native (Expo):

```ts
import * as WebBrowser from 'expo-web-browser';
import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';

const API = 'https://your-app.apps.mdrn.io';
const REDIRECT = 'com.example.app:/signed-in';
const b64url = (s: string) => s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const random = () => b64url(btoa(String.fromCharCode(...Crypto.getRandomBytes(32))));

export async function signIn() {
  const verifier = random(), state = random();
  const challenge = b64url(await Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, verifier, { encoding: Crypto.CryptoEncoding.BASE64 }));
  const query = new URLSearchParams({ redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256', state });
  const result = await WebBrowser.openAuthSessionAsync(`${API}/mobile/start?${query}`, REDIRECT);
  if (result.type !== 'success') return;
  const back = new URL(result.url);
  if (back.searchParams.get('state') !== state) throw new Error('state mismatch');
  const tokens = await (await fetch(`${API}/mobile/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', code: back.searchParams.get('code'), code_verifier: verifier, redirect_uri: REDIRECT }),
  })).json();
  await SecureStore.setItemAsync('refresh_token', tokens.refresh_token);
  return tokens.access_token as string;
}

// Then: fetch(`${API}/api/notes`, { headers: { Authorization: `Bearer ${accessToken}` } })
```

## How `src/mdrn.ts` calls MDRN

It reads errors the same way as MDRN's SDKs. A refused call throws `ProductError` with the HTTP
status and a code: the code from MDRN's error envelope, `HTTP_ERROR` when the body is not one, or
`UNEXPECTED_REDIRECT` for a 3xx, which is never followed. A product URL must be https (plain http
only to `localhost`, `127.0.0.1` or `[::1]`, for local development); MDRN always injects https
URLs. Calls time out after 10 seconds and are never retried for you.

## Billing

Every call to this backend runs your Worker, so each one counts as **Requests** and **CPU time**
on your MDRN bill, whether it comes from a browser or an app. What a route then does is counted on
that product's own meters: Database reads and writes, Files reads and writes, Emails. The hosted
sign-in pages are MDRN's, and file bytes travel between the client and Files without passing
through the Worker. The in-memory rate limiter costs nothing; the daily mail cap reads and writes
one Database record per message. See https://mdrn.io/docs/billing for prices.

## Develop

```sh
npm install
npm test            # node --test against an in-memory stand-in for MDRN
npm run typecheck
```

Requires Node 22.18 or later, which runs TypeScript directly; `.node-version` names the exact
version MDRN builds with, and CI uses it. The tests exercise the routes
through `app.fetch` exactly as MDRN delivers requests; deploy to a Sandbox environment to try it
against the real products.
