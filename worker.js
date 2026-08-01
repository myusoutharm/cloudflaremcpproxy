import { DurableObject } from "cloudflare:workers";

/**
 * Cloudflare Worker OAuth proxy for remote MCP clients such as Claude and ChatGPT.
 * OAuth state is stored in a Durable Object so authorization codes are single-use
 * and refresh tokens rotate with replay detection.
 */

const JSON_HEADERS = { "Content-Type": "application/json" };
const HTML_HEADERS = { "Content-Type": "text/html; charset=utf-8" };
const TOKEN_HEADERS = {
  "Cache-Control": "no-store",
  Pragma: "no-cache",
};
const AUTHORIZATION_HTML_HEADERS = {
  ...TOKEN_HEADERS,
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
};
const ACCESS_TOKEN_TTL_SECONDS = 3600;
const AUTH_CODE_TTL_SECONDS = 300;
const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
const PASSWORD_WINDOW_SECONDS = 15 * 60;
const PASSWORD_FAILURE_LIMIT = 5;
const MAX_FORM_BODY_BYTES = 16 * 1024;
const ALLOWED_SCOPES = new Set(["mcp", "offline_access"]);

/** Returns a JSON response with optional additional headers. */
function jsonResponse(body, status = 200, additionalHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_HEADERS, ...additionalHeaders },
  });
}

/** Returns a non-cacheable OAuth JSON response. */
function oauthJsonResponse(body, status = 200, additionalHeaders = {}) {
  return jsonResponse(body, status, { ...TOKEN_HEADERS, ...additionalHeaders });
}

/** Returns a non-cacheable HTML response. */
function htmlResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: { ...HTML_HEADERS, ...AUTHORIZATION_HTML_HEADERS },
  });
}

/** Returns the configured HTTPS public origin of this Worker. */
function getBaseUrl(env) {
  return env.OAUTH_PUBLIC_ORIGIN;
}

/** Returns the canonical protected MCP resource URL. */
function getCanonicalResource(env) {
  return `${getBaseUrl(env)}/mcp`;
}

/** Builds OAuth metadata for the preconfigured confidential client. */
function getOAuthMetadata(env) {
  const baseUrl = getBaseUrl(env);
  return {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: [...ALLOWED_SCOPES],
    resource_indicators_supported: true,
  };
}

/** Builds RFC 9728 metadata for the protected MCP resource. */
function getProtectedResourceMetadata(env) {
  const baseUrl = getBaseUrl(env);
  return {
    resource: `${baseUrl}/mcp`,
    authorization_servers: [baseUrl],
    bearer_methods_supported: ["header"],
    scopes_supported: [...ALLOWED_SCOPES],
  };
}

/** Parses exact redirect URIs configured for OAuth clients. */
function getAllowedRedirectUris(env) {
  return (env.OAUTH_ALLOWED_REDIRECT_URIS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

/** Checks whether a redirect URI uses HTTPS or a permitted loopback HTTP host. */
function isSecureRedirectUri(value) {
  try {
    const url = new URL(value);
    if (url.username || url.password || url.hash) {
      return false;
    }
    if (url.protocol === "https:") {
      return true;
    }
    const loopbackHosts = new Set(["localhost", "127.0.0.1", "[::1]"]);
    return url.protocol === "http:" && loopbackHosts.has(url.hostname);
  } catch {
    return false;
  }
}

/** Checks a redirect URI against the exact configured allowlist. */
function isAllowedRedirectUri(redirectUri, env) {
  return isSecureRedirectUri(redirectUri) && getAllowedRedirectUris(env).includes(redirectUri);
}

/** Allows authorization posts from the Worker or configured OAuth client origins. */
function isAllowedAuthorizationOrigin(requestOrigin, env) {
  if (!requestOrigin || requestOrigin === env.OAUTH_PUBLIC_ORIGIN) {
    return true;
  }
  return getAllowedRedirectUris(env).some((redirectUri) => {
    try {
      return new URL(redirectUri).origin === requestOrigin;
    } catch {
      return false;
    }
  });
}

/** Escapes text inserted into the authorization HTML page. */
function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}

/** Encodes bytes using unpadded base64url. */
function base64UrlEncodeBytes(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

/** Encodes text using unpadded base64url. */
function base64UrlEncodeText(value) {
  return base64UrlEncodeBytes(new TextEncoder().encode(value));
}

/** Decodes unpadded base64url into bytes. */
function base64UrlDecodeToBytes(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

/** Decodes base64url JSON content. */
function base64UrlDecodeToJson(value) {
  return JSON.parse(new TextDecoder().decode(base64UrlDecodeToBytes(value)));
}

/** Imports the access-token signing secret as an HMAC key. */
async function importSigningKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/** Signs a JWT signing input with the configured HMAC key. */
async function signValue(value, env) {
  const key = await importSigningKey(env.OAUTH_SIGNING_SECRET);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return base64UrlEncodeBytes(new Uint8Array(signature));
}

/** Calculates an S256 PKCE challenge. */
async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64UrlEncodeBytes(new Uint8Array(digest));
}

/** Creates a cryptographically random opaque OAuth credential. */
function createOpaqueToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncodeBytes(bytes);
}

/** Creates a signed access token bound to this Worker's MCP resource. */
async function createAccessToken(clientId, scope, issuer, resource, env, familyId = null) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "HS256", typ: "JWT" };
  const payload = {
    typ: "access_token",
    iss: issuer,
    aud: resource,
    client_id: clientId,
    scope,
    iat: now,
    exp: now + ACCESS_TOKEN_TTL_SECONDS,
    jti: crypto.randomUUID(),
  };
  if (familyId) {
    payload.family_id = familyId;
  }
  const encodedHeader = base64UrlEncodeText(JSON.stringify(header));
  const encodedPayload = base64UrlEncodeText(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  return `${signingInput}.${await signValue(signingInput, env)}`;
}

/** Verifies an access token and all MCP authorization constraints. */
async function verifyAccessToken(request, env) {
  const authHeader = request.headers.get("Authorization") ?? "";
  const bearerMatch = authHeader.match(/^Bearer\s+(\S+)\s*$/i);
  if (!bearerMatch) {
    return { ok: false, reason: "missing_bearer" };
  }

  try {
    const token = bearerMatch[1];
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new Error("invalid_token");
    }
    const [encodedHeader, encodedPayload, providedSignature] = parts;
    const header = base64UrlDecodeToJson(encodedHeader);
    if (header.alg !== "HS256" || header.typ !== "JWT") {
      throw new Error("invalid_header");
    }

    const key = await importSigningKey(env.OAUTH_SIGNING_SECRET);
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const isValid = await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlDecodeToBytes(providedSignature),
      new TextEncoder().encode(signingInput),
    );
    if (!isValid) {
      throw new Error("invalid_signature");
    }

    const payload = base64UrlDecodeToJson(encodedPayload);
    const now = Math.floor(Date.now() / 1000);
    const requiredScope = new Set(String(payload.scope ?? "").split(/\s+/));
    if (
      payload.typ !== "access_token"
      || payload.exp <= now
      || payload.iss !== getBaseUrl(env)
      || payload.aud !== getCanonicalResource(env)
      || payload.client_id !== env.OAUTH_CLIENT_ID
      || !requiredScope.has("mcp")
    ) {
      throw new Error("invalid_claims");
    }
    if (payload.family_id && await getOAuthState(env).isFamilyRevoked(payload.family_id)) {
      throw new Error("revoked_token_family");
    }
    return { ok: true, payload };
  } catch {
    return { ok: false, reason: "invalid_or_expired_token" };
  }
}

/** Returns a normalized requested scope string. */
function getRequestedScope(value) {
  return value?.trim().replace(/\s+/g, " ") || "mcp";
}

/** Checks that requested scopes are known and grant MCP access. */
function isScopeValid(scope) {
  const scopes = scope.split(" ").filter(Boolean);
  return scopes.includes("mcp") && scopes.every((value) => ALLOWED_SCOPES.has(value));
}

/** Checks the configured static OAuth client ID. */
function isClientIdValid(clientId, env) {
  return Boolean(clientId) && clientId === env.OAUTH_CLIENT_ID;
}

/** Checks the required confidential-client secret. */
function isClientSecretValid(clientSecret, env) {
  return Boolean(clientSecret) && clientSecret === env.OAUTH_CLIENT_SECRET;
}

/** Builds a redirect URI while preserving any existing query and fragment. */
function buildRedirectUri(redirectUri, params) {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(params)) {
    if (value) {
      url.searchParams.set(key, value);
    }
  }
  return url.toString();
}

/** Returns a standard non-cacheable OAuth error response. */
function oauthErrorResponse(error, description, status = 400) {
  return oauthJsonResponse({ error, error_description: description }, status);
}

/** Returns a non-cacheable redirect that always converts POST to GET. */
function oauthRedirectResponse(location) {
  return new Response(null, {
    status: 303,
    headers: { Location: location, ...TOKEN_HEADERS, "Referrer-Policy": "no-referrer" },
  });
}

/** Redirects a validated OAuth client with an authorization error. */
function oauthErrorRedirect(redirectUri, state, error, description) {
  return oauthRedirectResponse(
    buildRedirectUri(redirectUri, {
      error,
      error_description: description,
      state,
    }),
  );
}

/** Renders the mandatory shared-password authorization page. */
function renderAuthorizePage(query) {
  const hiddenFields = [
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
    "resource",
  ].map((name) => {
    const value = query.get(name) ?? "";
    return `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`;
  }).join("");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MCP Access Approval</title>
  <style>
    body { font-family: sans-serif; background: #f6f7f9; color: #111; padding: 32px; }
    .card { max-width: 520px; margin: 0 auto; background: #fff; border: 1px solid #ddd; border-radius: 12px; padding: 24px; }
    h1 { font-size: 20px; margin: 0 0 12px; }
    p { line-height: 1.5; }
    label { display: block; margin: 16px 0; font-weight: 600; }
    input[type="password"] { box-sizing: border-box; width: 100%; padding: 10px; margin-top: 8px; }
    button { background: #111; color: #fff; border: 0; border-radius: 8px; padding: 12px 18px; cursor: pointer; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Approve MCP Access</h1>
    <p>Enter the MCP authorization password to continue.</p>
    <form method="post" action="/authorize" autocomplete="off">
      ${hiddenFields}
      <label>Password <input type="password" name="user_password" required autocomplete="off" autocapitalize="none" spellcheck="false"></label>
      <button type="submit">Approve</button>
    </form>
  </div>
</body>
</html>`;
}

/** Returns the single Durable Object used for OAuth credential state. */
function getOAuthState(env) {
  return env.OAUTH_STATE.getByName("global");
}

/** Stores and atomically consumes short-lived OAuth credentials. */
export class OAuthState extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS authorization_codes (
        token TEXT PRIMARY KEY,
        payload TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        token TEXT PRIMARY KEY,
        family_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS revoked_families (
        family_id TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS password_attempts (
        client_ip TEXT PRIMARY KEY,
        window_started INTEGER NOT NULL,
        failures INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS client_auth_attempts (
        client_ip TEXT PRIMARY KEY,
        window_started INTEGER NOT NULL,
        failures INTEGER NOT NULL
      );
    `);
  }

  /** Stores an opaque authorization code and its PKCE constraints. */
  storeAuthorizationCode(token, payload) {
    const now = Math.floor(Date.now() / 1000);
    this.sql.exec("DELETE FROM authorization_codes WHERE expires_at <= ?", now);
    this.sql.exec(
      "INSERT INTO authorization_codes (token, payload, expires_at) VALUES (?, ?, ?)",
      token,
      JSON.stringify(payload),
      payload.exp,
    );
  }

  /** Exchanges an authorization code and stores its first refresh token atomically. */
  exchangeAuthorizationCode(token, expected, refreshToken) {
    return this.ctx.storage.transactionSync(() => {
      const now = Math.floor(Date.now() / 1000);
      this.sql.exec("DELETE FROM refresh_tokens WHERE expires_at <= ?", now);
      const row = this.sql.exec(
        "SELECT payload, expires_at, used FROM authorization_codes WHERE token = ?",
        token,
      ).toArray()[0];
      if (!row || row.expires_at <= now) {
        return { status: "invalid" };
      }

      const payload = JSON.parse(row.payload);
      if (
        payload.client_id !== expected.client_id
        || payload.redirect_uri !== expected.redirect_uri
        || payload.resource !== expected.resource
        || payload.code_challenge !== expected.code_challenge
      ) {
        return { status: "invalid" };
      }
      if (row.used) {
        this.sql.exec(
          "INSERT OR REPLACE INTO revoked_families (family_id, expires_at) VALUES (?, ?)",
          payload.family_id,
          now + REFRESH_TOKEN_TTL_SECONDS,
        );
        return { status: "replayed" };
      }
      const refreshPayload = {
        client_id: payload.client_id,
        scope: payload.scope,
        resource: payload.resource,
        exp: now + REFRESH_TOKEN_TTL_SECONDS,
      };
      this.sql.exec("UPDATE authorization_codes SET used = 1 WHERE token = ?", token);
      this.sql.exec(
        "INSERT INTO refresh_tokens (token, family_id, payload, expires_at) VALUES (?, ?, ?, ?)",
        refreshToken,
        payload.family_id,
        JSON.stringify(refreshPayload),
        refreshPayload.exp,
      );
      return { status: "consumed", payload };
    });
  }

  /** Rotates a refresh token atomically and revokes its family on replay. */
  rotateRefreshToken(token, expected, replacementToken) {
    return this.ctx.storage.transactionSync(() => {
      const now = Math.floor(Date.now() / 1000);
      this.sql.exec("DELETE FROM refresh_tokens WHERE expires_at <= ?", now);
      const row = this.sql.exec(
        "SELECT family_id, payload, expires_at, used FROM refresh_tokens WHERE token = ?",
        token,
      ).toArray()[0];
      if (!row || row.expires_at <= now) {
        return null;
      }
      if (row.used) {
        this.sql.exec(
          "INSERT OR REPLACE INTO revoked_families (family_id, expires_at) VALUES (?, ?)",
          row.family_id,
          now + REFRESH_TOKEN_TTL_SECONDS,
        );
        return null;
      }

      const revoked = this.sql.exec(
        "SELECT 1 FROM revoked_families WHERE family_id = ?",
        row.family_id,
      ).toArray().length > 0;
      const payload = JSON.parse(row.payload);
      if (
        revoked
        || payload.client_id !== expected.client_id
        || payload.resource !== expected.resource
      ) {
        return null;
      }
      const originalScopes = new Set(payload.scope.split(" "));
      const requestedScope = expected.scope || payload.scope;
      const requestedScopes = requestedScope.split(" ");
      if (requestedScopes.some((scope) => !originalScopes.has(scope))) {
        return { status: "invalid_scope" };
      }
      const replacementPayload = {
        ...payload,
        scope: requestedScope,
        exp: now + REFRESH_TOKEN_TTL_SECONDS,
      };
      this.sql.exec("UPDATE refresh_tokens SET used = 1 WHERE token = ?", token);
      this.sql.exec(
        "INSERT INTO refresh_tokens (token, family_id, payload, expires_at) VALUES (?, ?, ?, ?)",
        replacementToken,
        row.family_id,
        JSON.stringify(replacementPayload),
        replacementPayload.exp,
      );
      return { status: "rotated", family_id: row.family_id, payload: replacementPayload };
    });
  }

  /** Checks whether an OAuth token family has been revoked. */
  isFamilyRevoked(familyId) {
    const now = Math.floor(Date.now() / 1000);
    this.sql.exec("DELETE FROM revoked_families WHERE expires_at <= ?", now);
    return this.sql.exec(
      "SELECT 1 FROM revoked_families WHERE family_id = ?",
      familyId,
    ).toArray().length > 0;
  }

  /** Applies a per-IP failure limit to one of the credential tables. */
  recordCredentialAttempt(tableName, clientIp, credentialCorrect) {
    const allowedTables = new Set(["password_attempts", "client_auth_attempts"]);
    if (!allowedTables.has(tableName)) {
      throw new Error("invalid_attempt_table");
    }
    return this.ctx.storage.transactionSync(() => {
      const now = Math.floor(Date.now() / 1000);
      this.sql.exec(
        `DELETE FROM ${tableName} WHERE window_started + ? <= ?`,
        PASSWORD_WINDOW_SECONDS,
        now,
      );
      if (credentialCorrect) {
        this.sql.exec(`DELETE FROM ${tableName} WHERE client_ip = ?`, clientIp);
        return { blocked: false };
      }

      const row = this.sql.exec(
        `SELECT window_started, failures FROM ${tableName} WHERE client_ip = ?`,
        clientIp,
      ).toArray()[0];
      if (!row || row.window_started + PASSWORD_WINDOW_SECONDS <= now) {
        this.sql.exec(
          `INSERT OR REPLACE INTO ${tableName} (client_ip, window_started, failures) VALUES (?, ?, 1)`,
          clientIp,
          now,
        );
        return { blocked: false };
      }
      if (row.failures >= PASSWORD_FAILURE_LIMIT) {
        return { blocked: true };
      }
      this.sql.exec(
        `UPDATE ${tableName} SET failures = failures + 1 WHERE client_ip = ?`,
        clientIp,
      );
      return { blocked: false };
    });
  }

  /** Applies a per-IP failure limit to the shared authorization password. */
  recordPasswordAttempt(clientIp, passwordCorrect) {
    return this.recordCredentialAttempt("password_attempts", clientIp, passwordCorrect);
  }

  /** Applies a per-IP failure limit to confidential-client authentication. */
  recordClientAuthAttempt(clientIp, credentialsCorrect) {
    return this.recordCredentialAttempt("client_auth_attempts", clientIp, credentialsCorrect);
  }

  /** Checks whether an IP is currently blocked for one credential type. */
  isCredentialBlocked(tableName, clientIp) {
    const allowedTables = new Set(["password_attempts", "client_auth_attempts"]);
    if (!allowedTables.has(tableName)) {
      throw new Error("invalid_attempt_table");
    }
    const now = Math.floor(Date.now() / 1000);
    this.sql.exec(
      `DELETE FROM ${tableName} WHERE window_started + ? <= ?`,
      PASSWORD_WINDOW_SECONDS,
      now,
    );
    const row = this.sql.exec(
      `SELECT failures FROM ${tableName} WHERE client_ip = ?`,
      clientIp,
    ).toArray()[0];
    return Boolean(row && row.failures >= PASSWORD_FAILURE_LIMIT);
  }

  /** Checks whether an IP is blocked from authorization-password attempts. */
  isPasswordBlocked(clientIp) {
    return this.isCredentialBlocked("password_attempts", clientIp);
  }

  /** Checks whether an IP is blocked from confidential-client attempts. */
  isClientAuthBlocked(clientIp) {
    return this.isCredentialBlocked("client_auth_attempts", clientIp);
  }
}

/** Builds an access-token response for a refresh token already stored atomically. */
async function buildAccessTokenPair(clientId, scope, resource, env, familyId, refreshToken) {
  const issuer = getBaseUrl(env);
  const accessToken = await createAccessToken(clientId, scope, issuer, resource, env, familyId);
  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    refresh_token: refreshToken,
    scope,
  };
}

/** Parses a size-limited application/x-www-form-urlencoded request body. */
async function parseUrlEncodedForm(request) {
  const contentType = request.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/x-www-form-urlencoded") {
    return { error: "Expected application/x-www-form-urlencoded request body.", status: 415 };
  }
  const contentLength = Number(request.headers.get("Content-Length") ?? 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_FORM_BODY_BYTES) {
    return { error: "Request body is too large.", status: 413 };
  }

  const reader = request.body?.getReader();
  if (!reader) {
    return { body: new URLSearchParams() };
  }
  const chunks = [];
  let totalBytes = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    totalBytes += value.byteLength;
    if (totalBytes > MAX_FORM_BODY_BYTES) {
      await reader.cancel();
      return { error: "Request body is too large.", status: 413 };
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { body: new URLSearchParams(new TextDecoder().decode(bytes)) };
}

/** Checks the fixed-length base64url grammar of an S256 challenge. */
function isPkceChallengeValid(value) {
  return /^[A-Za-z0-9_-]{43}$/.test(value);
}

/** Checks RFC 7636 verifier length and unreserved-character grammar. */
function isPkceVerifierValid(value) {
  return /^[A-Za-z0-9\-._~]{43,128}$/.test(value);
}

/** Validates an authorization request and requires password approval. */
async function handleAuthorize(request, env) {
  const url = new URL(request.url);
  let query = url.searchParams;
  if (request.method === "POST") {
    const requestOrigin = request.headers.get("Origin");
    if (!isAllowedAuthorizationOrigin(requestOrigin, env)) {
      return oauthErrorResponse("invalid_request", "Cross-origin authorization POST is not allowed.", 403);
    }
    const clientIp = request.headers.get("CF-Connecting-IP") ?? "unknown";
    if (await getOAuthState(env).isPasswordBlocked(clientIp)) {
      return htmlResponse("<h1>Too Many Attempts</h1><p>Try again later.</p>", 429);
    }
    const parsed = await parseUrlEncodedForm(request);
    if (!parsed.body) {
      return oauthErrorResponse("invalid_request", parsed.error, parsed.status);
    }
    query = parsed.body;
  }
  const responseType = query.get("response_type") ?? "";
  const clientId = query.get("client_id") ?? "";
  const redirectUri = query.get("redirect_uri") ?? "";
  const scope = getRequestedScope(query.get("scope"));
  const state = query.get("state") ?? "";
  const codeChallenge = query.get("code_challenge") ?? "";
  const codeChallengeMethod = query.get("code_challenge_method") ?? "";
  const resource = query.get("resource") ?? "";

  if (responseType !== "code") {
    return oauthErrorResponse("unsupported_response_type", "Only response_type=code is supported.");
  }
  if (!isClientIdValid(clientId, env)) {
    return oauthErrorResponse("invalid_client", "Unknown client_id.", 401);
  }
  if (!redirectUri || !isAllowedRedirectUri(redirectUri, env)) {
    return oauthErrorResponse("invalid_request", "redirect_uri is missing or not allowed.");
  }
  if (!isScopeValid(scope)) {
    return oauthErrorRedirect(redirectUri, state, "invalid_scope", "Requested scope is not allowed.");
  }
  if (resource !== getCanonicalResource(env)) {
    return oauthErrorRedirect(redirectUri, state, "invalid_target", "resource must identify this MCP server.");
  }
  if (!isPkceChallengeValid(codeChallenge) || codeChallengeMethod !== "S256") {
    return oauthErrorRedirect(redirectUri, state, "invalid_request", "S256 PKCE is required.");
  }
  if (request.method === "GET") {
    return htmlResponse(renderAuthorizePage(url.searchParams));
  }

  const submittedPassword = query.get("user_password") ?? "";
  const passwordCorrect = submittedPassword === env.OAUTH_USER_PASSWORD;
  const clientIp = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const attempt = await getOAuthState(env).recordPasswordAttempt(clientIp, passwordCorrect);
  if (attempt.blocked) {
    return htmlResponse("<h1>Too Many Attempts</h1><p>Try again later.</p>", 429);
  }
  if (!passwordCorrect) {
    return htmlResponse("<h1>Unauthorized</h1><p>Invalid password.</p>", 401);
  }

  const now = Math.floor(Date.now() / 1000);
  const code = createOpaqueToken();
  await getOAuthState(env).storeAuthorizationCode(code, {
    client_id: clientId,
    redirect_uri: redirectUri,
    scope,
    resource,
    code_challenge: codeChallenge,
    family_id: crypto.randomUUID(),
    exp: now + AUTH_CODE_TTL_SECONDS,
  });
  return oauthRedirectResponse(buildRedirectUri(redirectUri, { code, state }));
}

/** Parses one confidential-client authentication method from a token request. */
function getClientAuthentication(request, body) {
  const authHeader = request.headers.get("Authorization") ?? "";
  const formClientId = body.get("client_id") ?? "";
  const formClientSecret = body.get("client_secret") ?? "";
  if (!authHeader) {
    return { client_id: formClientId, client_secret: formClientSecret, method: "client_secret_post" };
  }
  const basicMatch = authHeader.match(/^Basic\s+(\S+)\s*$/i);
  if (!basicMatch || formClientSecret) {
    return null;
  }

  try {
    const decoded = atob(basicMatch[1]);
    const separatorIndex = decoded.indexOf(":");
    if (separatorIndex < 0) {
      return null;
    }
    const clientId = decodeURIComponent(decoded.slice(0, separatorIndex).replaceAll("+", " "));
    const clientSecret = decodeURIComponent(decoded.slice(separatorIndex + 1).replaceAll("+", " "));
    if (formClientId && formClientId !== clientId) {
      return null;
    }
    return { client_id: clientId, client_secret: clientSecret, method: "client_secret_basic" };
  } catch {
    return null;
  }
}

/** Exchanges a single-use authorization code for tokens. */
async function handleAuthorizationCodeGrant(body, clientAuth, env) {
  const clientId = clientAuth.client_id;
  const code = body.get("code") ?? "";
  const redirectUri = body.get("redirect_uri") ?? "";
  const codeVerifier = body.get("code_verifier") ?? "";
  const resource = body.get("resource") ?? "";
  if (!code || !redirectUri || !codeVerifier || !resource) {
    return oauthErrorResponse("invalid_request", "code, redirect_uri, code_verifier, and resource are required.");
  }
  if (resource !== getCanonicalResource(env)) {
    return oauthErrorResponse("invalid_target", "resource must identify this MCP server.");
  }
  if (!isPkceVerifierValid(codeVerifier)) {
    return oauthErrorResponse("invalid_request", "code_verifier does not meet RFC 7636 requirements.");
  }

  const codeChallenge = await sha256Base64Url(codeVerifier);
  const refreshToken = createOpaqueToken();
  const consumed = await getOAuthState(env).exchangeAuthorizationCode(code, {
    client_id: clientId,
    redirect_uri: redirectUri,
    resource,
    code_challenge: codeChallenge,
  }, refreshToken);
  if (consumed.status !== "consumed") {
    return oauthErrorResponse("invalid_grant", "Authorization code is invalid, expired, or already used.");
  }
  return oauthJsonResponse(await buildAccessTokenPair(
    clientId,
    consumed.payload.scope,
    resource,
    env,
    consumed.payload.family_id,
    refreshToken,
  ));
}

/** Rotates a refresh token and rejects replayed token families. */
async function handleRefreshTokenGrant(body, clientAuth, env) {
  const clientId = clientAuth.client_id;
  const refreshToken = body.get("refresh_token") ?? "";
  const resource = body.get("resource") ?? "";
  const requestedScopeValue = body.get("scope");
  const requestedScope = requestedScopeValue === null ? null : getRequestedScope(requestedScopeValue);
  if (!refreshToken || !resource) {
    return oauthErrorResponse("invalid_request", "refresh_token and resource are required.");
  }
  if (resource !== getCanonicalResource(env)) {
    return oauthErrorResponse("invalid_target", "resource must identify this MCP server.");
  }
  if (requestedScope !== null && !isScopeValid(requestedScope)) {
    return oauthErrorResponse("invalid_scope", "Requested scope is not allowed.");
  }

  const replacementToken = createOpaqueToken();
  const consumed = await getOAuthState(env).rotateRefreshToken(refreshToken, {
    client_id: clientId,
    resource,
    scope: requestedScope,
  }, replacementToken);
  if (!consumed) {
    return oauthErrorResponse("invalid_grant", "Refresh token is invalid, expired, reused, or revoked.");
  }
  if (consumed.status === "invalid_scope") {
    return oauthErrorResponse("invalid_scope", "Requested scope exceeds the original grant.");
  }
  return oauthJsonResponse(await buildAccessTokenPair(
    clientId,
    consumed.payload.scope,
    resource,
    env,
    consumed.family_id,
    replacementToken,
  ));
}

/** Issues a short-lived access token for an authenticated machine client. */
async function handleClientCredentialsGrant(body, clientAuth, env) {
  const clientId = clientAuth.client_id;
  const scope = getRequestedScope(body.get("scope"));
  const resource = body.get("resource") ?? "";
  if (!isScopeValid(scope) || scope.includes("offline_access")) {
    return oauthErrorResponse("invalid_scope", "Client credentials supports only the mcp scope.");
  }
  if (resource !== getCanonicalResource(env)) {
    return oauthErrorResponse("invalid_target", "resource must identify this MCP server.");
  }

  const accessToken = await createAccessToken(clientId, scope, getBaseUrl(env), resource, env);
  return oauthJsonResponse({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    scope,
  });
}

/** Dispatches supported OAuth token grants. */
async function handleTokenRequest(request, env) {
  const clientIp = request.headers.get("CF-Connecting-IP") ?? "unknown";
  if (await getOAuthState(env).isClientAuthBlocked(clientIp)) {
    return oauthErrorResponse("invalid_client", "Too many failed client authentication attempts.", 429);
  }
  const parsed = await parseUrlEncodedForm(request);
  if (!parsed.body) {
    return oauthErrorResponse("invalid_request", parsed.error, parsed.status);
  }
  const body = parsed.body;
  const clientAuth = getClientAuthentication(request, body);
  const credentialsCorrect = Boolean(clientAuth)
    && isClientIdValid(clientAuth.client_id, env)
    && isClientSecretValid(clientAuth.client_secret, env);
  const attempt = await getOAuthState(env).recordClientAuthAttempt(clientIp, credentialsCorrect);
  if (attempt.blocked) {
    return oauthErrorResponse("invalid_client", "Too many failed client authentication attempts.", 429);
  }
  if (!credentialsCorrect) {
    const challenge = /^Basic\s/i.test(request.headers.get("Authorization") ?? "")
      ? { "WWW-Authenticate": "Basic realm=\"oauth-token\"" }
      : {};
    return oauthJsonResponse({
      error: "invalid_client",
      error_description: "Client authentication failed.",
    }, 401, challenge);
  }

  const grantType = body.get("grant_type") ?? "";
  if (grantType === "authorization_code") {
    return handleAuthorizationCodeGrant(body, clientAuth, env);
  }
  if (grantType === "refresh_token") {
    return handleRefreshTokenGrant(body, clientAuth, env);
  }
  if (grantType === "client_credentials") {
    return handleClientCredentialsGrant(body, clientAuth, env);
  }
  return oauthErrorResponse("unsupported_grant_type", "Unsupported grant_type.");
}

/** Returns an MCP 401 response with RFC 9728 discovery metadata. */
function unauthorizedMcpResponse(env) {
  const metadataUrl = `${getBaseUrl(env)}/.well-known/oauth-protected-resource`;
  return jsonResponse(
    { error: "unauthorized" },
    401,
    { "WWW-Authenticate": `Bearer resource_metadata="${metadataUrl}"` },
  );
}

/** Builds the trusted Worker-to-origin header set. */
function buildProxyHeaders(requestHeaders, env) {
  const headers = new Headers(requestHeaders);
  for (const name of [
    "Authorization",
    "Cookie",
    "CF-Access-Jwt-Assertion",
    "CF-Access-Authenticated-User-Email",
    "Origin",
  ]) {
    headers.delete(name);
  }
  headers.set("CF-Access-Client-Id", env.CF_SERVICE_TOKEN_ID);
  headers.set("CF-Access-Client-Secret", env.CF_SERVICE_TOKEN_SECRET);
  headers.delete("host");
  return headers;
}

/** Proxies an authenticated MCP request through Cloudflare Access. */
async function handleMcpProxy(request, env) {
  const tokenCheck = await verifyAccessToken(request, env);
  if (!tokenCheck.ok) {
    console.log(JSON.stringify({
      route: "/mcp",
      method: request.method,
      auth_ok: false,
      reason: tokenCheck.reason,
      has_authorization_header: request.headers.has("Authorization"),
      has_session_id_header: request.headers.has("mcp-session-id"),
    }));
    return unauthorizedMcpResponse(env);
  }

  const requestUrl = new URL(request.url);
  const targetUrl = new URL(requestUrl.pathname + requestUrl.search, env.MCP_ORIGIN);
  const method = request.method.toUpperCase();
  const proxiedRequest = new Request(targetUrl.toString(), {
    method,
    headers: buildProxyHeaders(request.headers, env),
    body: method === "GET" || method === "HEAD" ? undefined : request.body,
    duplex: "half",
    redirect: "manual",
  });
  const upstreamResponse = await fetch(proxiedRequest);
  if (upstreamResponse.status >= 300 && upstreamResponse.status < 400) {
    console.error("MCP origin returned an unexpected redirect", upstreamResponse.status);
    return jsonResponse({ error: "unexpected_upstream_redirect" }, 502);
  }
  console.log(JSON.stringify({
    route: "/mcp",
    method: request.method,
    auth_ok: true,
    client_id: tokenCheck.payload.client_id,
    upstream_status: upstreamResponse.status,
    has_upstream_session_id: upstreamResponse.headers.has("mcp-session-id"),
  }));
  return upstreamResponse;
}

/** Validates all required Worker bindings and security-sensitive URLs. */
function validateEnv(env) {
  const required = [
    "MCP_ORIGIN",
    "OAUTH_PUBLIC_ORIGIN",
    "CF_SERVICE_TOKEN_ID",
    "CF_SERVICE_TOKEN_SECRET",
    "OAUTH_CLIENT_ID",
    "OAUTH_CLIENT_SECRET",
    "OAUTH_SIGNING_SECRET",
    "OAUTH_USER_PASSWORD",
    "OAUTH_ALLOWED_REDIRECT_URIS",
    "OAUTH_STATE",
  ];
  const missing = required.filter((key) => !env[key]);
  if (missing.length > 0) {
    return jsonResponse({
      error: "server_misconfigured",
      error_description: `Missing required Worker secrets/variables: ${missing.join(", ")}`,
    }, 500);
  }

  try {
    const origin = new URL(env.MCP_ORIGIN);
    if (
      origin.protocol !== "https:"
      || origin.username
      || origin.password
      || origin.pathname !== "/"
      || origin.search
      || origin.hash
    ) {
      throw new Error("invalid_origin");
    }
  } catch {
    return jsonResponse({
      error: "server_misconfigured",
      error_description: "MCP_ORIGIN must be an HTTPS origin without credentials, path, query, or fragment.",
    }, 500);
  }

  try {
    const publicOrigin = new URL(env.OAUTH_PUBLIC_ORIGIN);
    if (
      publicOrigin.protocol !== "https:"
      || publicOrigin.username
      || publicOrigin.password
      || publicOrigin.pathname !== "/"
      || publicOrigin.search
      || publicOrigin.hash
      || publicOrigin.origin !== env.OAUTH_PUBLIC_ORIGIN
    ) {
      throw new Error("invalid_public_origin");
    }
  } catch {
    return jsonResponse({
      error: "server_misconfigured",
      error_description: "OAUTH_PUBLIC_ORIGIN must be an HTTPS origin without credentials, path, trailing slash, query, or fragment.",
    }, 500);
  }

  const invalidRedirectUri = getAllowedRedirectUris(env).find((uri) => !isSecureRedirectUri(uri));
  if (invalidRedirectUri) {
    return jsonResponse({
      error: "server_misconfigured",
      error_description: `Redirect URI must use HTTPS or loopback HTTP: ${invalidRedirectUri}`,
    }, 500);
  }
  if (env.OAUTH_SIGNING_SECRET.length < 32 || env.OAUTH_USER_PASSWORD.length < 20) {
    return jsonResponse({
      error: "server_misconfigured",
      error_description: "OAUTH_SIGNING_SECRET must be 32+ characters and OAUTH_USER_PASSWORD must be 20+ characters.",
    }, 500);
  }
  if (env.OAUTH_CLIENT_SECRET.length < 32) {
    return jsonResponse({
      error: "server_misconfigured",
      error_description: "OAUTH_CLIENT_SECRET must be at least 32 characters.",
    }, 500);
  }
  return null;
}

export default {
  /** Routes OAuth, discovery, and MCP requests. */
  async fetch(request, env) {
    const envError = validateEnv(env);
    if (envError) {
      return envError;
    }

    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:" || url.origin !== env.OAUTH_PUBLIC_ORIGIN) {
        return jsonResponse({ error: "invalid_request_origin" }, 400);
      }
      if (url.pathname === "/authorize" && (request.method === "GET" || request.method === "POST")) {
        return handleAuthorize(request, env);
      }
      if (url.pathname === "/oauth/token" && request.method === "POST") {
        return handleTokenRequest(request, env);
      }
      if (url.pathname === "/.well-known/oauth-authorization-server") {
        return jsonResponse(getOAuthMetadata(env));
      }
      if (
        url.pathname === "/.well-known/oauth-protected-resource"
        || url.pathname === "/.well-known/oauth-protected-resource/mcp"
      ) {
        return jsonResponse(getProtectedResourceMetadata(env));
      }
      if (url.pathname === "/mcp") {
        return handleMcpProxy(request, env);
      }
      return jsonResponse({ error: "not_found" }, 404);
    } catch (error) {
      console.error("Unhandled MCP OAuth proxy error", error);
      return jsonResponse({ error: "server_error" }, 500);
    }
  },
};