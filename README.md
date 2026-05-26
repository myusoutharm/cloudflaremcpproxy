# Cloudflare MCP OAuth Proxy

Minimal Cloudflare Worker project for OAuth-only MCP clients such as ChatGPT or Claude.ai.

## Files

- `worker.js` — OAuth token endpoint and MCP proxy
- `wrangler.jsonc` — Cloudflare Worker project config

## Required secrets / variables

Set these in Cloudflare Workers before deployment:

- `MCP_ORIGIN` — protected upstream MCP host, for example `https://mcp.mydomain.com`
- `CF_SERVICE_TOKEN_ID`
- `CF_SERVICE_TOKEN_SECRET`
- `OAUTH_CLIENT_ID`
- `OAUTH_CLIENT_SECRET`

## Client settings

Users should configure the Worker host, not the upstream MCP host:

- MCP server URL: `https://mcp-api.mydomain.com/mcp`
- Token URL: `https://mcp-api.mydomain.com/oauth/token`

## GitHub integration

If deploying through Cloudflare GitHub integration, use this folder as the Worker project root.
