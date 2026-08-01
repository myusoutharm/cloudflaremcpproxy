/**
 * Confidential OAuth proxy for Claude and ChatGPT MCP connections.
 *
 * The AI client authenticates with OAUTH_CLIENT_ID/OAUTH_CLIENT_SECRET.
 * The Worker then presents a Cloudflare Access service token to MCP_ORIGIN.
 */

const JSON_HEADERS = { "Content-Type": "application/json" };
const TOKEN_HEADERS = { "Cache-Control": "no-store", Pragma: "no-cache" };
const ACCESS_TOKEN_TTL_SECONDS = 3600;
const AUTH_CODE_TTL_SECONDS = 300;
const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
const MAX_TOKEN_BODY_BYTES = 16 * 1024;
const ALLOWED_SCOPES = new Set(["mcp", "offline_access"]);

/** Returns a JSON response. */
function jsonResponse(body, status = 200, additionalHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_HEADERS, ...additionalHeaders },
  });
}

/** Returns a non-cacheable OAuth response. */
function oauthResponse(body, status = 200, additionalHeaders = {}) {
  return jsonResponse(body, status, { ...TOKEN_HEADERS, ...additionalHeaders });
}

/** Returns a standard OAuth error response. */
function oauthError(error, description, status = 400, additionalHeaders = {}) {
  return oauthResponse({ error, error_description: description }, status, additionalHeaders);
}

/** Returns the configured public Worker origin. */
function getPublicOrigin(env) {
  return env.OAUTH_PUBLIC_ORIGIN;
}

/** Returns the canonical MCP resource identifier. */
function getMcpResource(env) {
  return `${getPublicOrigin(env)}/mcp`;
}

/** Parses configured exact redirect URIs. */
function getAllowedRedirectUris(env) {
  return env.OAUTH_ALLOWED_REDIRECT_URIS
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

/** Checks that a redirect URI is safe and exactly configured. */
function isAllowedRedirectUri(value, env) {
  if (!getAllowedRedirectUris(env).includes(value)) {
    return false;
  }
  try {
    const url = new URL(value);
    const loopbackHosts = new Set(["localhost", "127.0.0.1", "[::1]"]);
    return !url.username
      && !url.password
      && !url.hash
      && (url.protocol === "https:" || (url.protocol === "http:" && loopbackHosts.has(url.hostname)));
  } catch {
    return false;
  }
}

/** Normalizes a requested OAuth scope. */
function normalizeScope(value) {
  return value?.trim().replace(/\s+/g, " ") || "mcp";
}

/** Checks that a scope grants MCP access and contains only supported values. */
function isScopeValid(scope) {
  const values = scope.split(" ").filter(Boolean);
  return values.includes("mcp") && values.every((value) => ALLOWED_SCOPES.has(value));
}

/** Encodes bytes as unpadded base64url. */
function base64UrlEncodeBytes(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

/** Encodes text as unpadded base64url. */
function base64UrlEncodeText(value) {
  return base64UrlEncodeBytes(new TextEncoder().encode(value));
}

/** Decodes unpadded base64url into bytes. */
function base64UrlDecodeBytes(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

/** Decodes base64url JSON content. */
function base64UrlDecodeJson(value) {
  return JSON.parse(new TextDecoder().decode(base64UrlDecodeBytes(value)));
}

/** Imports the HMAC signing key. */
async function importSigningKey(env) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.OAUTH_SIGNING_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/** Creates a signed self-contained OAuth token. */
async function createSignedToken(payload, env) {
  const header = base64UrlEncodeText(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64UrlEncodeText(JSON.stringify(payload));
  const signingInput = `${header}.${body}`;
  const signature = await crypto.subtle.sign(
    "HMAC",
    await importSigningKey(env),
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${base64UrlEncodeBytes(new Uint8Array(signature))}`;
}

/** Verifies a signed OAuth token and returns its payload. */
async function verifySignedToken(token, expectedType, env) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("invalid_token");
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const header = base64UrlDecodeJson(encodedHeader);
  if (header.alg !== "HS256" || header.typ !== "JWT") {
    throw new Error("invalid_header");
  }
  const validSignature = await crypto.subtle.verify(
    "HMAC",
    await importSigningKey(env),
    base64UrlDecodeBytes(encodedSignature),
    new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`),
  );
  if (!validSignature) {
    throw new Error("invalid_signature");
  }
  const payload = base64UrlDecodeJson(encodedPayload);
  const now = Math.floor(Date.now() / 1000);
  if (payload.typ !== expectedType || payload.iss !== getPublicOrigin(env) || payload.exp <= now) {
    throw new Error("invalid_claims");
  }
  return payload;
}

/** Calculates an S256 PKCE challenge. */
async function createPkceChallenge(verifier) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64UrlEncodeBytes(new Uint8Array(digest));
}

/** Checks RFC 7636 verifier grammar. */
function isPkceVerifierValid(value) {
  return /^[A-Za-z0-9\-._~]{43,128}$/.test(value);
}

/** Builds a redirect URI with OAuth response parameters. */
function buildRedirectUri(redirectUri, params) {
  const url = new URL(redirectUri);
  for (const [name, value] of Object.entries(params)) {
    if (value) {
      url.searchParams.set(name, value);
    }
  }
  return url.toString();
}

/** Returns a non-cacheable redirect that converts requests to GET. */
function oauthRedirect(location) {
  return new Response(null, {
    status: 303,
    headers: { Location: location, ...TOKEN_HEADERS, "Referrer-Policy": "no-referrer" },
  });
}

/** Returns authorization-server metadata. */
function getAuthorizationMetadata(env) {
  const origin = getPublicOrigin(env);
  return {
    issuer: origin,
    authorization_endpoint: `${origin}/authorize`,
    token_endpoint: `${origin}/oauth/token`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: [...ALLOWED_SCOPES],
    resource_indicators_supported: true,
  };
}

/** Returns RFC 9728 protected-resource metadata. */
function getProtectedResourceMetadata(env) {
  return {
    resource: getMcpResource(env),
    authorization_servers: [getPublicOrigin(env)],
    bearer_methods_supported: ["header"],
    scopes_supported: [...ALLOWED_SCOPES],
  };
}

/** Validates and auto-approves a confidential-client authorization request. */
async function handleAuthorize(request, env) {
  const query = new URL(request.url).searchParams;
  const responseType = query.get("response_type") ?? "";
  const clientId = query.get("client_id") ?? "";
  const redirectUri = query.get("redirect_uri") ?? "";
  const scope = normalizeScope(query.get("scope"));
  const state = query.get("state") ?? "";
  const codeChallenge = query.get("code_challenge") ?? "";
  const challengeMethod = query.get("code_challenge_method") ?? "";
  const resource = query.get("resource") ?? "";

  if (responseType !== "code") {
    return oauthError("unsupported_response_type", "Only response_type=code is supported.");
  }
  if (clientId !== env.OAUTH_CLIENT_ID) {
    return oauthError("invalid_client", "Unknown client_id.", 401);
  }
  if (!isAllowedRedirectUri(redirectUri, env)) {
    return oauthError("invalid_request", "redirect_uri is missing or not allowed.");
  }
  if (!isScopeValid(scope)) {
    return oauthRedirect(buildRedirectUri(redirectUri, { error: "invalid_scope", state }));
  }
  if (resource !== getMcpResource(env)) {
    return oauthRedirect(buildRedirectUri(redirectUri, { error: "invalid_target", state }));
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(codeChallenge) || challengeMethod !== "S256") {
    return oauthRedirect(buildRedirectUri(redirectUri, { error: "invalid_request", state }));
  }

  const now = Math.floor(Date.now() / 1000);
  const code = await createSignedToken({
    typ: "authorization_code",
    iss: getPublicOrigin(env),
    client_id: clientId,
    redirect_uri: redirectUri,
    scope,
    resource,
    code_challenge: codeChallenge,
    iat: now,
    exp: now + AUTH_CODE_TTL_SECONDS,
  }, env);
  return oauthRedirect(buildRedirectUri(redirectUri, { code, state }));
}

/** Parses a bounded URL-encoded token request. */
async function parseTokenBody(request) {
  const contentType = request.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/x-www-form-urlencoded") {
    return null;
  }
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > MAX_TOKEN_BODY_BYTES) {
    return null;
  }
  return new URLSearchParams(text);
}

/** Parses client_secret_basic or client_secret_post credentials. */
function getClientCredentials(request, body) {
  const authHeader = request.headers.get("Authorization") ?? "";
  const formClientId = body.get("client_id") ?? "";
  const formClientSecret = body.get("client_secret") ?? "";
  if (!authHeader) {
    return { clientId: formClientId, clientSecret: formClientSecret, method: "post" };
  }
  const match = authHeader.match(/^Basic\s+(\S+)\s*$/i);
  if (!match || formClientSecret) {
    return null;
  }
  try {
    const decoded = atob(match[1]);
    const separator = decoded.indexOf(":");
    if (separator < 0) {
      return null;
    }
    const clientId = decodeURIComponent(decoded.slice(0, separator).replaceAll("+", " "));
    const clientSecret = decodeURIComponent(decoded.slice(separator + 1).replaceAll("+", " "));
    if (formClientId && formClientId !== clientId) {
      return null;
    }
    return { clientId, clientSecret, method: "basic" };
  } catch {
    return null;
  }
}

/** Issues signed access and refresh tokens. */
async function issueTokenPair(clientId, scope, resource, env) {
  const now = Math.floor(Date.now() / 1000);
  const common = {
    iss: getPublicOrigin(env),
    client_id: clientId,
    scope,
    resource,
    aud: resource,
    iat: now,
  };
  return {
    access_token: await createSignedToken({
      ...common,
      typ: "access_token",
      exp: now + ACCESS_TOKEN_TTL_SECONDS,
    }, env),
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    refresh_token: await createSignedToken({
      ...common,
      typ: "refresh_token",
      exp: now + REFRESH_TOKEN_TTL_SECONDS,
    }, env),
    scope,
  };
}

/** Exchanges an authorization code for access and refresh tokens. */
async function handleAuthorizationCodeGrant(body, clientId, env) {
  const code = body.get("code") ?? "";
  const redirectUri = body.get("redirect_uri") ?? "";
  const verifier = body.get("code_verifier") ?? "";
  const resource = body.get("resource") ?? "";
  if (!code || !redirectUri || !isPkceVerifierValid(verifier) || resource !== getMcpResource(env)) {
    return oauthError("invalid_request", "code, redirect_uri, valid code_verifier, and resource are required.");
  }
  try {
    const payload = await verifySignedToken(code, "authorization_code", env);
    const challenge = await createPkceChallenge(verifier);
    if (
      payload.client_id !== clientId
      || payload.redirect_uri !== redirectUri
      || payload.resource !== resource
      || payload.code_challenge !== challenge
    ) {
      throw new Error("code_binding_mismatch");
    }
    return oauthResponse(await issueTokenPair(clientId, payload.scope, resource, env));
  } catch {
    return oauthError("invalid_grant", "Authorization code is invalid or expired.");
  }
}

/** Exchanges a refresh token for a new token pair. */
async function handleRefreshTokenGrant(body, clientId, env) {
  const refreshToken = body.get("refresh_token") ?? "";
  const resource = body.get("resource") ?? "";
  if (!refreshToken || resource !== getMcpResource(env)) {
    return oauthError("invalid_request", "refresh_token and resource are required.");
  }
  try {
    const payload = await verifySignedToken(refreshToken, "refresh_token", env);
    if (payload.client_id !== clientId || payload.resource !== resource) {
      throw new Error("refresh_binding_mismatch");
    }
    const requestedScopeValue = body.get("scope");
    const scope = requestedScopeValue === null ? payload.scope : normalizeScope(requestedScopeValue);
    const originalScopes = new Set(payload.scope.split(" "));
    if (!isScopeValid(scope) || scope.split(" ").some((value) => !originalScopes.has(value))) {
      return oauthError("invalid_scope", "Requested scope exceeds the original grant.");
    }
    return oauthResponse(await issueTokenPair(clientId, scope, resource, env));
  } catch {
    return oauthError("invalid_grant", "Refresh token is invalid or expired.");
  }
}

/** Issues a short-lived machine access token without a refresh token. */
async function handleClientCredentialsGrant(body, clientId, env) {
  const scope = normalizeScope(body.get("scope"));
  const resource = body.get("resource") ?? "";
  if (scope !== "mcp") {
    return oauthError("invalid_scope", "Client credentials supports only the mcp scope.");
  }
  if (resource !== getMcpResource(env)) {
    return oauthError("invalid_target", "resource must identify this MCP server.");
  }
  const now = Math.floor(Date.now() / 1000);
  return oauthResponse({
    access_token: await createSignedToken({
      typ: "access_token",
      iss: getPublicOrigin(env),
      aud: resource,
      resource,
      client_id: clientId,
      scope,
      iat: now,
      exp: now + ACCESS_TOKEN_TTL_SECONDS,
    }, env),
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    scope,
  });
}

/** Authenticates the confidential client and dispatches token grants. */
async function handleToken(request, env) {
  const body = await parseTokenBody(request);
  if (!body) {
    return oauthError("invalid_request", "Expected a URL-encoded token request under 16 KiB.");
  }
  const credentials = getClientCredentials(request, body);
  if (
    !credentials
    || credentials.clientId !== env.OAUTH_CLIENT_ID
    || credentials.clientSecret !== env.OAUTH_CLIENT_SECRET
  ) {
    const headers = credentials?.method === "basic"
      ? { "WWW-Authenticate": "Basic realm=\"oauth-token\"" }
      : {};
    return oauthError("invalid_client", "Client authentication failed.", 401, headers);
  }

  const grantType = body.get("grant_type") ?? "";
  if (grantType === "authorization_code") {
    return handleAuthorizationCodeGrant(body, credentials.clientId, env);
  }
  if (grantType === "refresh_token") {
    return handleRefreshTokenGrant(body, credentials.clientId, env);
  }
  if (grantType === "client_credentials") {
    return handleClientCredentialsGrant(body, credentials.clientId, env);
  }
  return oauthError("unsupported_grant_type", "Unsupported grant_type.");
}

/** Verifies an MCP bearer token. */
async function verifyMcpAccess(request, env) {
  const match = (request.headers.get("Authorization") ?? "").match(/^Bearer\s+(\S+)\s*$/i);
  if (!match) {
    return null;
  }
  try {
    const payload = await verifySignedToken(match[1], "access_token", env);
    const scopes = new Set(String(payload.scope ?? "").split(" "));
    if (
      payload.client_id !== env.OAUTH_CLIENT_ID
      || payload.aud !== getMcpResource(env)
      || payload.resource !== getMcpResource(env)
      || !scopes.has("mcp")
    ) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

/** Returns an MCP discovery challenge. */
function unauthorizedMcpResponse(env) {
  const metadataUrl = `${getPublicOrigin(env)}/.well-known/oauth-protected-resource`;
  return jsonResponse(
    { error: "unauthorized" },
    401,
    { "WWW-Authenticate": `Bearer resource_metadata="${metadataUrl}"` },
  );
}

/** Builds headers for the trusted Cloudflare Access origin hop. */
function buildProxyHeaders(requestHeaders, env) {
  const headers = new Headers(requestHeaders);
  for (const name of ["Authorization", "Cookie", "Origin", "CF-Access-Jwt-Assertion"]) {
    headers.delete(name);
  }
  headers.set("CF-Access-Client-Id", env.CF_SERVICE_TOKEN_ID);
  headers.set("CF-Access-Client-Secret", env.CF_SERVICE_TOKEN_SECRET);
  headers.delete("host");
  return headers;
}

/** Proxies an authenticated MCP request to the Access-protected origin. */
async function handleMcp(request, env) {
  if (!await verifyMcpAccess(request, env)) {
    return unauthorizedMcpResponse(env);
  }
  const requestUrl = new URL(request.url);
  const targetUrl = new URL(`${requestUrl.pathname}${requestUrl.search}`, env.MCP_ORIGIN);
  const method = request.method.toUpperCase();
  const upstreamResponse = await fetch(new Request(targetUrl, {
    method,
    headers: buildProxyHeaders(request.headers, env),
    body: method === "GET" || method === "HEAD" ? undefined : request.body,
    duplex: "half",
    redirect: "manual",
  }));
  if (upstreamResponse.status >= 300 && upstreamResponse.status < 400) {
    return jsonResponse({ error: "unexpected_upstream_redirect" }, 502);
  }
  const responseHeaders = new Headers(upstreamResponse.headers);
  responseHeaders.delete("Set-Cookie");
  return new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    statusText: upstreamResponse.statusText,
    headers: responseHeaders,
  });
}

/** Validates required bindings and fixed HTTPS origins. */
function validateEnv(env) {
  const required = [
    "MCP_ORIGIN",
    "OAUTH_PUBLIC_ORIGIN",
    "CF_SERVICE_TOKEN_ID",
    "CF_SERVICE_TOKEN_SECRET",
    "OAUTH_CLIENT_ID",
    "OAUTH_CLIENT_SECRET",
    "OAUTH_SIGNING_SECRET",
    "OAUTH_ALLOWED_REDIRECT_URIS",
  ];
  const missing = required.filter((name) => !env[name]);
  if (missing.length > 0) {
    return jsonResponse({
      error: "server_misconfigured",
      error_description: `Missing required Worker variables: ${missing.join(", ")}`,
    }, 500);
  }
  try {
    const publicOrigin = new URL(env.OAUTH_PUBLIC_ORIGIN);
    const mcpOrigin = new URL(env.MCP_ORIGIN);
    if (
      publicOrigin.protocol !== "https:"
      || publicOrigin.origin !== env.OAUTH_PUBLIC_ORIGIN
      || mcpOrigin.protocol !== "https:"
      || mcpOrigin.pathname !== "/"
      || env.OAUTH_SIGNING_SECRET.length < 32
      || getAllowedRedirectUris(env).some((uri) => !isAllowedRedirectUri(uri, env))
    ) {
      throw new Error("invalid_configuration");
    }
  } catch {
    return jsonResponse({
      error: "server_misconfigured",
      error_description: "Check HTTPS origins, redirect URIs, and the 32+ character signing secret.",
    }, 500);
  }
  return null;
}

export default {
  /** Routes OAuth discovery, token, authorization, and MCP requests. */
  async fetch(request, env) {
    const configurationError = validateEnv(env);
    if (configurationError) {
      return configurationError;
    }
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:" || url.origin !== getPublicOrigin(env)) {
        return jsonResponse({ error: "invalid_request_origin" }, 400);
      }
      if (url.pathname === "/authorize" && request.method === "GET") {
        return handleAuthorize(request, env);
      }
      if (url.pathname === "/oauth/token" && request.method === "POST") {
        return handleToken(request, env);
      }
      if (url.pathname === "/.well-known/oauth-authorization-server") {
        return jsonResponse(getAuthorizationMetadata(env));
      }
      if (
        url.pathname === "/.well-known/oauth-protected-resource"
        || url.pathname === "/.well-known/oauth-protected-resource/mcp"
      ) {
        return jsonResponse(getProtectedResourceMetadata(env));
      }
      if (url.pathname === "/mcp") {
        return handleMcp(request, env);
      }
      return jsonResponse({ error: "not_found" }, 404);
    } catch (error) {
      console.error("MCP OAuth proxy error", error);
      return jsonResponse({ error: "server_error" }, 500);
    }
  },
};