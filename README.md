# Cloudflare MCP OAuth Proxy

Minimal Cloudflare Worker project for Claude.ai and ChatGPT remote MCP connections.

## Files

- `worker.js` — OAuth endpoints, metadata, and MCP proxy
- `wrangler.jsonc` — Cloudflare Worker project config

## Deploy behavior

`wrangler.jsonc` sets `keep_vars: true` so GitHub/Workers redeploys do not wipe runtime variables saved in the Cloudflare dashboard.

Without `keep_vars: true`, dashboard text variables such as `MCP_ORIGIN` and `OAUTH_ALLOWED_REDIRECT_URIS` can disappear after a deploy because Wrangler treats configuration as the source of truth.

## Required secrets / variables

Set these in Cloudflare Workers before deployment:

- `MCP_ORIGIN` — protected upstream MCP host, for example `https://mcp.mydomain.com`
- `CF_SERVICE_TOKEN_ID`
- `CF_SERVICE_TOKEN_SECRET`
- `OAUTH_CLIENT_ID`
- `OAUTH_SIGNING_SECRET` — strong random secret used to sign auth codes and tokens
- `OAUTH_ALLOWED_REDIRECT_URIS` — comma-separated exact callback URLs allowed by the Worker

Optional:

- `OAUTH_CLIENT_SECRET` — if you want confidential-client or client-credentials support
- `OAUTH_AUTO_APPROVE` — `true` or `false`; defaults to `true`
- `OAUTH_USER_PASSWORD` — if set, `/authorize` requires this shared password before approval and disables auto-approve for that step

## Client settings

Users should configure the Worker host, not the upstream MCP host:

- MCP server URL: `https://mcp-api.mydomain.com/mcp`
- Authorization URL: `https://mcp-api.mydomain.com/authorize`
- Token URL: `https://mcp-api.mydomain.com/oauth/token`
- Registration URL: `https://mcp-api.mydomain.com/register`
- Auth server base: `https://mcp-api.mydomain.com`

## Example redirect URIs

Add exact callback URLs to `OAUTH_ALLOWED_REDIRECT_URIS`.

Examples:

- Claude.ai: `https://claude.ai/api/mcp/auth_callback`
- ChatGPT: add the exact callback URL shown by ChatGPT during setup

## OAuth behavior

- `authorization_code` with PKCE is supported for Claude.ai and ChatGPT
- `refresh_token` is supported
- `client_credentials` is supported when `OAUTH_CLIENT_SECRET` is set
- No external database or KV is required; codes and tokens are signed and self-contained

## GitHub integration

If deploying through Cloudflare GitHub integration, use this folder as the Worker project root.
