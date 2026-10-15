// Small Web Crypto helpers. Everything here runs on the Workers runtime and on Node 22.
const encoder = new TextEncoder();

export function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64url(text: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return null;
  const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4);
  try {
    return Uint8Array.from(atob(padded), char => char.charCodeAt(0));
  } catch {
    return null;
  }
}

/** 32 random bytes, base64url: 43 characters. */
export const randomToken = () => base64url(crypto.getRandomValues(new Uint8Array(32)));

export async function sha256(text: string): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(text))));
}

/** Compares two strings in time that does not depend on where they differ. */
export function safeEqual(a: string, b: string): boolean {
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  let difference = left.length ^ right.length;
  for (let i = 0; i < Math.max(left.length, right.length); i++) difference |= (left[i] ?? 0) ^ (right[i] ?? 0);
  return difference === 0;
}

/** A stable, opaque key for a user, used to name their collections. MDRN user ids are already
 * opaque; hashing keeps collection names short and uniform whatever the id looks like. */
export async function userKey(userId: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(`user:${userId}`)));
  return 'u' + Array.from(digest.slice(0, 16), b => b.toString(16).padStart(2, '0')).join('');
}

const hmacKeys = new Map<string, Promise<CryptoKey>>();
export function hmacKey(secret: string): Promise<CryptoKey> {
  let key = hmacKeys.get(secret);
  if (!key) {
    key = crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    hmacKeys.set(secret, key);
  }
  return key;
}

export async function hmacSign(secret: string, message: string): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(secret), encoder.encode(message))));
}

/** Verifies an HMAC in constant time (crypto.subtle.verify does the comparison). */
export async function hmacVerify(secret: string, message: string, signature: string): Promise<boolean> {
  const bytes = fromBase64url(signature);
  if (!bytes || bytes.length !== 32) return false;
  return crypto.subtle.verify('HMAC', await hmacKey(secret), bytes, encoder.encode(message));
}
