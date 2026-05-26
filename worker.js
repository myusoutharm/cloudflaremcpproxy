/**
 * Cloudflare Worker OAuth proxy for remote MCP clients such as Claude and ChatGPT.
 *
 * Supported routes:
 * - GET/POST /authorize
 * - POST /oauth/token
 * - POST /register
 * - GET /.well-known/oauth-authorization-server
 * - GET /.well-known/openid-configuration
 * - /mcp
 *
 * Design notes:
 * - Uses signed self-contained auth codes / tokens so no KV or database is required.
 * - Supports authorization_code + PKCE for browser-based OAuth clients.
 * - Supports refresh_token and client_credentials for compatibility.
 * - Proxies MCP traffic to the protected upstream origin with Cloudflare Access headers.
 */

const JSON_HEADERS = { "Content-Type": "application/json" };
const HTML_HEADERS = { "Content-Type": "text/html; charset=utf-8" };
const ACCESS_TOKEN_TTL_SECONDS = 3600;
const AUTH_CODE_TTL_SECONDS = 300;
const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: JSON_HEADERS,
  });
}

function htmlResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: HTML_HEADERS,
  });
}

function getBaseUrl(request) {
  return new URL(request.url).origin;
}

function getOAuthMetadata(request) {
  const base = getBaseUrl(request);
  return {
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
    code_challenge_methods_supported: ["S256", "plain"],
    scopes_supported: ["mcp", "offline_access"],
  };
}

function getAllowedRedirectUris(env) {
  return (env.OAUTH_ALLOWED_REDIRECT_URIS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function isAllowedRedirectUri(redirectUri, env) {
  const allowedRedirectUris = getAllowedRedirectUris(env);
  return allowedRedirectUris.length > 0 && allowedRedirectUris.includes(redirectUri);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}

function base64UrlEncodeBytes(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlEncodeText(value) {
  return base64UrlEncodeBytes(new TextEncoder().encode(value));
}

function base64UrlDecodeToBytes(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64UrlDecodeToJson(value) {
  const bytes = base64UrlDecodeToBytes(value);
  return JSON.parse(new TextDecoder().decode(bytes));
}

async function importSigningKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

async function signValue(value, env) {
  const key = await importSigningKey(env.OAUTH_SIGNING_SECRET);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return base64UrlEncodeBytes(new Uint8Array(signature));
}

async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64UrlEncodeBytes(new Uint8Array(digest));
}

async function createSignedToken(payload, env) {
  const header = { alg: "HS256", typ: "JWT" };
  const encodedHeader = base64UrlEncodeText(JSON.stringify(header));
  const encodedPayload = base64UrlEncodeText(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = await signValue(signingInput, env);
  return `${signingInput}.${signature}`;
}

async function verifySignedToken(token, env, expectedType) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("invalid_token");
  }

  const [encodedHeader, encodedPayload, providedSignature] = parts;
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const expectedSignature = await signValue(signingInput, env);
  if (providedSignature !== expectedSignature) {
    throw new Error("invalid_signature");
  }

  const payload = base64UrlDecodeToJson(encodedPayload);
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp < now) {
    throw new Error("expired_token");
  }
  if (expectedType && payload.typ !== expectedType) {
    throw new Error("invalid_token_type");
  }
  return payload;
}

function buildProxyHeaders(requestHeaders, env) {
  const headers = new Headers(requestHeaders);
  headers.set("CF-Access-Client-Id", env.CF_SERVICE_TOKEN_ID);
  headers.set("CF-Access-Client-Secret", env.CF_SERVICE_TOKEN_SECRET);
  headers.delete("host");
  return headers;
}

function isClientIdValid(clientId, env) {
  return Boolean(clientId) && clientId === env.OAUTH_CLIENT_ID;
}

function isClientSecretValid(clientSecret, env) {
  return Boolean(clientSecret) && clientSecret === env.OAUTH_CLIENT_SECRET;
}

function getRequestedScope(value) {
  return value?.trim() || "mcp";
}

async function issueAccessTokenTokenPair(clientId, scope, resource, env) {
  const now = Math.floor(Date.now() / 1000);
  const accessToken = await createSignedToken({
    typ: "access_token",
    client_id: clientId,
    scope,
    resource,
    exp: now + ACCESS_TOKEN_TTL_SECONDS,
  }, env);

  const refreshToken = await createSignedToken({
    typ: "refresh_token",
    client_id: clientId,
    scope,
    resource,
    exp: now + REFRESH_TOKEN_TTL_SECONDS,
  }, env);

  return {
    access_token: accessToken,
    token_type: "bearer",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    refresh_token: refreshToken,
    scope,
  };
}

function buildRedirectUri(redirectUri, params) {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(params)) {
    if (value) {
      url.searchParams.set(key, value);
    }
  }
  return url.toString();
}

function oauthErrorResponse(error, description, status = 400) {
  return jsonResponse({
    error,
    error_description: description,
  }, status);
}

function oauthErrorRedirect(redirectUri, state, error, description) {
  return Response.redirect(
    buildRedirectUri(redirectUri, {
      error,
      error_description: description,
      state,
    }),
    302,
  );
}

function renderAuthorizePage(query, requirePassword) {
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

  const passwordField = requirePassword
    ? '<label>Password <input type="password" name="user_password" required></label>'
    : "";

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
    input[type="password"] { width: 100%; padding: 10px; margin-top: 8px; }
    button { background: #111; color: #fff; border: 0; border-radius: 8px; padding: 12px 18px; cursor: pointer; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Approve MCP Access</h1>
    <p>This app wants access to your MCP proxy.</p>
    <form method="post" action="/authorize">
      ${hiddenFields}
      ${passwordField}
      <button type="submit">Approve</button>
    </form>
  </div>
</body>
</html>`;
}

async function createAuthorizationCode(clientId, redirectUri, scope, resource, codeChallenge, codeChallengeMethod, env) {
  const now = Math.floor(Date.now() / 1000);
  return createSignedToken({
    typ: "authorization_code",
    client_id: clientId,
    redirect_uri: redirectUri,
    scope,
    resource,
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod,
    exp: now + AUTH_CODE_TTL_SECONDS,
  }, env);
}

async function handleAuthorize(request, env) {
  const url = new URL(request.url);
  const query = request.method === "GET"
    ? url.searchParams
    : await request.formData();

  const responseType = query.get("response_type") ?? "";
  const clientId = query.get("client_id") ?? "";
  const redirectUri = query.get("redirect_uri") ?? "";
  const scope = getRequestedScope(query.get("scope"));
  const state = query.get("state") ?? "";
  const codeChallenge = query.get("code_challenge") ?? "";
  const codeChallengeMethod = query.get("code_challenge_method") ?? "plain";
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
  if (!codeChallenge) {
    return oauthErrorRedirect(redirectUri, state, "invalid_request", "code_challenge is required.");
  }
  if (!["S256", "plain"].includes(codeChallengeMethod)) {
    return oauthErrorRedirect(redirectUri, state, "invalid_request", "Unsupported code_challenge_method.");
  }

  const requirePassword = Boolean(env.OAUTH_USER_PASSWORD);
  const autoApprove = (env.OAUTH_AUTO_APPROVE ?? "true").toLowerCase() === "true";
  const shouldRenderApprovalPage = request.method === "GET" && (!autoApprove || requirePassword);

  if (shouldRenderApprovalPage) {
    return htmlResponse(renderAuthorizePage(url.searchParams, requirePassword));
  }

  if (request.method === "POST" && requirePassword) {
    const submittedPassword = query.get("user_password") ?? "";
    if (submittedPassword !== env.OAUTH_USER_PASSWORD) {
      return htmlResponse("<h1>Unauthorized</h1><p>Invalid password.</p>", 401);
    }
  }

  const code = await createAuthorizationCode(
    clientId,
    redirectUri,
    scope,
    resource,
    codeChallenge,
    codeChallengeMethod,
    env,
  );

  return Response.redirect(
    buildRedirectUri(redirectUri, { code, state }),
    302,
  );
}

async function handleAuthorizationCodeGrant(body, env) {
  const clientId = body.get("client_id") ?? "";
  const clientSecret = body.get("client_secret") ?? "";
  const code = body.get("code") ?? "";
  const redirectUri = body.get("redirect_uri") ?? "";
  const codeVerifier = body.get("code_verifier") ?? "";

  if (!isClientIdValid(clientId, env)) {
    return oauthErrorResponse("invalid_client", "Unknown client_id.", 401);
  }
  if (!code || !redirectUri || !codeVerifier) {
    return oauthErrorResponse("invalid_request", "code, redirect_uri, and code_verifier are required.");
  }

  let payload;
  try {
    payload = await verifySignedToken(code, env, "authorization_code");
  } catch {
    return oauthErrorResponse("invalid_grant", "Authorization code is invalid or expired.", 401);
  }

  if (payload.client_id !== clientId || payload.redirect_uri !== redirectUri) {
    return oauthErrorResponse("invalid_grant", "Authorization code does not match client or redirect URI.", 401);
  }

  if (clientSecret && !isClientSecretValid(clientSecret, env)) {
    return oauthErrorResponse("invalid_client", "Invalid client_secret.", 401);
  }

  const expectedChallenge = payload.code_challenge_method === "S256"
    ? await sha256Base64Url(codeVerifier)
    : codeVerifier;

  if (expectedChallenge !== payload.code_challenge) {
    return oauthErrorResponse("invalid_grant", "PKCE verification failed.", 401);
  }

  return jsonResponse(await issueAccessTokenTokenPair(
    clientId,
    payload.scope ?? "mcp",
    payload.resource ?? "",
    env,
  ));
}

async function handleRefreshTokenGrant(body, env) {
  const clientId = body.get("client_id") ?? "";
  const clientSecret = body.get("client_secret") ?? "";
  const refreshToken = body.get("refresh_token") ?? "";

  if (!isClientIdValid(clientId, env)) {
    return oauthErrorResponse("invalid_client", "Unknown client_id.", 401);
  }
  if (clientSecret && !isClientSecretValid(clientSecret, env)) {
    return oauthErrorResponse("invalid_client", "Invalid client_secret.", 401);
  }

  let payload;
  try {
    payload = await verifySignedToken(refreshToken, env, "refresh_token");
  } catch {
    return oauthErrorResponse("invalid_grant", "Refresh token is invalid or expired.", 401);
  }

  if (payload.client_id !== clientId) {
    return oauthErrorResponse("invalid_grant", "Refresh token client mismatch.", 401);
  }

  return jsonResponse(await issueAccessTokenTokenPair(
    clientId,
    payload.scope ?? "mcp",
    payload.resource ?? "",
    env,
  ));
}

async function handleClientCredentialsGrant(body, env) {
  const clientId = body.get("client_id") ?? "";
  const clientSecret = body.get("client_secret") ?? "";
  const scope = getRequestedScope(body.get("scope"));
  const resource = body.get("resource") ?? "";

  if (!isClientIdValid(clientId, env) || !isClientSecretValid(clientSecret, env)) {
    return oauthErrorResponse("invalid_client", "client_id or client_secret is invalid.", 401);
  }

  return jsonResponse(await issueAccessTokenTokenPair(clientId, scope, resource, env));
}

async function handleTokenRequest(request, env) {
  const body = await request.formData().catch(() => null);
  if (!body) {
    return oauthErrorResponse("invalid_request", "Expected application/x-www-form-urlencoded request body.");
  }

  const grantType = body.get("grant_type") ?? "";
  if (grantType === "authorization_code") {
    return handleAuthorizationCodeGrant(body, env);
  }
  if (grantType === "refresh_token") {
    return handleRefreshTokenGrant(body, env);
  }
  if (grantType === "client_credentials") {
    return handleClientCredentialsGrant(body, env);
  }

  return oauthErrorResponse("unsupported_grant_type", "Unsupported grant_type.");
}

async function verifyAccessToken(request, env) {
  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return null;
  }

  const token = authHeader.slice(7);
  try {
    const payload = await verifySignedToken(token, env, "access_token");
    if (payload.client_id !== env.OAUTH_CLIENT_ID) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

async function handleMcpProxy(request, env) {
  const accessTokenPayload = await verifyAccessToken(request, env);
  if (!accessTokenPayload) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }

  const requestUrl = new URL(request.url);
  const targetUrl = new URL(requestUrl.pathname + requestUrl.search, env.MCP_ORIGIN);
  const method = request.method.toUpperCase();

  const proxiedRequest = new Request(targetUrl.toString(), {
    method,
    headers: buildProxyHeaders(request.headers, env),
    body: method === "GET" || method === "HEAD" ? undefined : request.body,
    duplex: "half",
  });

  return fetch(proxiedRequest);
}

async function handleRegistration(request, env) {
  if (request.method !== "POST") {
    return oauthErrorResponse("invalid_request", "Use POST for client registration.");
  }

  const body = await request.json().catch(() => ({}));
  const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
  const allowedRedirectUris = getAllowedRedirectUris(env);

  const invalidRedirectUri = redirectUris.find((uri) => !allowedRedirectUris.includes(uri));
  if (invalidRedirectUri) {
    return oauthErrorResponse("invalid_client_metadata", `Redirect URI not allowed: ${invalidRedirectUri}`);
  }

  return jsonResponse({
    client_id: env.OAUTH_CLIENT_ID,
    client_secret: env.OAUTH_CLIENT_SECRET || undefined,
    redirect_uris: redirectUris,
    token_endpoint_auth_method: env.OAUTH_CLIENT_SECRET ? "client_secret_post" : "none",
    grant_types: ["authorization_code", "refresh_token", "client_credentials"],
    response_types: ["code"],
  }, 201);
}

function validateEnv(env) {
  const required = [
    "MCP_ORIGIN",
    "CF_SERVICE_TOKEN_ID",
    "CF_SERVICE_TOKEN_SECRET",
    "OAUTH_CLIENT_ID",
    "OAUTH_SIGNING_SECRET",
  ];

  const missing = required.filter((key) => !env[key]);
  if (missing.length > 0) {
    return jsonResponse({
      error: "server_misconfigured",
      error_description: `Missing required Worker secrets/variables: ${missing.join(", ")}`,
    }, 500);
  }

  if (getAllowedRedirectUris(env).length === 0) {
    return jsonResponse({
      error: "server_misconfigured",
      error_description: "Set OAUTH_ALLOWED_REDIRECT_URIS to one or more exact callback URLs.",
    }, 500);
  }

  return null;
}

function handleDebugEnv(env) {
  const allowedRedirectUris = getAllowedRedirectUris(env);
  return jsonResponse({
    mcp_origin_present: Boolean(env.MCP_ORIGIN),
    oauth_client_id_present: Boolean(env.OAUTH_CLIENT_ID),
    oauth_signing_secret_present: Boolean(env.OAUTH_SIGNING_SECRET),
    oauth_allowed_redirect_uris_present: Boolean(env.OAUTH_ALLOWED_REDIRECT_URIS),
    oauth_allowed_redirect_uris_count: allowedRedirectUris.length,
    oauth_allowed_redirect_uris_values: allowedRedirectUris,
    cf_service_token_id_present: Boolean(env.CF_SERVICE_TOKEN_ID),
    cf_service_token_secret_present: Boolean(env.CF_SERVICE_TOKEN_SECRET),
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/debug-env") {
      return handleDebugEnv(env);
    }

    const envError = validateEnv(env);
    if (envError) {
      return envError;
    }

    if (url.pathname === "/authorize" && (request.method === "GET" || request.method === "POST")) {
      return handleAuthorize(request, env);
    }

    if (url.pathname === "/oauth/token" && request.method === "POST") {
      return handleTokenRequest(request, env);
    }

    if (url.pathname === "/register") {
      return handleRegistration(request, env);
    }

    if (url.pathname === "/.well-known/oauth-authorization-server") {
      return jsonResponse(getOAuthMetadata(request));
    }

    if (url.pathname === "/.well-known/openid-configuration") {
      return jsonResponse(getOAuthMetadata(request));
    }

    if (url.pathname === "/mcp") {
      return handleMcpProxy(request, env);
    }

    return jsonResponse({ error: "not_found" }, 404);
  },
};
