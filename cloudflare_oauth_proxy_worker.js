/**
 * A very simple Cloudflare Worker OAuth proxy for OAuth-only MCP clients.
 *
 * Purpose:
 * - Expose a standard OAuth client-credentials token endpoint
 * - Proxy MCP requests to the protected Cloudflare Access origin
 * - Inject CF service-token headers on behalf of clients that cannot send them
 *
 * Expected routes:
 * - POST /oauth/token
 * - /mcp
 */

const JSON_HEADERS = { "Content-Type": "application/json" };

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: JSON_HEADERS,
  });
}

function buildProxyHeaders(requestHeaders, env) {
  const headers = new Headers(requestHeaders);
  headers.set("CF-Access-Client-Id", env.CF_SERVICE_TOKEN_ID);
  headers.set("CF-Access-Client-Secret", env.CF_SERVICE_TOKEN_SECRET);
  headers.delete("host");
  return headers;
}

async function handleTokenRequest(request, env) {
  const body = await request.formData().catch(() => null);
  const grantType = body?.get("grant_type");
  const clientId = body?.get("client_id");
  const clientSecret = body?.get("client_secret");

  if (grantType && grantType !== "client_credentials") {
    return jsonResponse({ error: "unsupported_grant_type" }, 400);
  }

  if (clientId !== env.OAUTH_CLIENT_ID || clientSecret !== env.OAUTH_CLIENT_SECRET) {
    return jsonResponse({ error: "invalid_client" }, 401);
  }

  return jsonResponse({
    access_token: env.OAUTH_CLIENT_SECRET,
    token_type: "bearer",
    expires_in: 86400,
  });
}

function isAuthorized(request, env) {
  const authHeader = request.headers.get("Authorization") ?? "";
  return authHeader === `Bearer ${env.OAUTH_CLIENT_SECRET}`;
}

async function handleMcpProxy(request, env) {
  if (!isAuthorized(request, env)) {
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/oauth/token" && request.method === "POST") {
      return handleTokenRequest(request, env);
    }

    if (url.pathname === "/mcp") {
      return handleMcpProxy(request, env);
    }

    return jsonResponse({ error: "not_found" }, 404);
  },
};
