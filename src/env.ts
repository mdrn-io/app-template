// What a release of this Worker receives from MDRN, and the few settings it reads.
//
// MDRN injects the MDRN_* bindings into every release of a service whose project has the
// products on (SQLite, Objects, Mail). You never set them yourself, and they are never
// visible to a browser: they exist only inside this Worker.

/** The service binding MDRN gives a release for every product call. A plain fetch() of the
 * app's own hostname cannot reach MDRN's product routes, so every call goes through this. */
export interface ProductsBinding {
  fetch(request: Request): Promise<Response>;
}

export interface Env {
  // Injected by MDRN.
  MDRN_PRODUCTS?: ProductsBinding;
  MDRN_PROJECT_ID?: string;
  MDRN_ENVIRONMENT?: string;
  MDRN_SQLITE_URL?: string;
  MDRN_SQLITE_TOKEN?: string;
  MDRN_OBJECTS_URL?: string;
  MDRN_OBJECTS_TOKEN?: string;
  MDRN_MAIL_URL?: string;
  MDRN_MAIL_TOKEN?: string;

  // Your own variables (console: Service -> Variables). All optional.
  /** Turns the mobile module on. At least 32 random characters; mark it secret. */
  MOBILE_TOKEN_SECRET?: string;
  /** Where the mobile sign-in may hand a code back to: a comma-separated list of exact URIs,
   * for example "https://example.com/app/signed-in,com.example.app:/signed-in". */
  MOBILE_REDIRECT_URIS?: string;
  /** Mails one signed-in user may send to themselves per UTC day (default 5). */
  MAIL_DAILY_LIMIT?: string;
}

/** Hono's environment type for this app: the bindings above plus what middleware sets. */
export type AppEnv = {
  Bindings: Env;
  Variables: {
    user: SignedInUser;
  };
};

/** Who is calling. `web` came through MDRN's sign-in cookie, `mobile` through this backend's own
 * bearer token (see src/mobile). */
export interface SignedInUser {
  id: string;
  via: 'web' | 'mobile';
  /** The MDRN identity token (web only): proves the session to MDRN's own /v1/auth/me. */
  identityToken?: string;
  /** The mobile session this access token belongs to (mobile only). */
  sessionId?: string;
}
