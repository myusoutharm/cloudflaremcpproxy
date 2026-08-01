# Cloudflare MCP OAuth Proxy

Minimal Cloudflare Worker for confidential OAuth connections from Claude.ai and ChatGPT to an MCP
server protected by Cloudflare Access.

The AI client authenticates with a preconfigured OAuth client ID and secret. The Worker validates
the OAuth token and forwards MCP traffic with a Cloudflare Access service token. No database,
Durable Object, approval page, or user password is required.

## Configuration

Set these as Cloudflare dashboard text variables:

- `MCP_ORIGIN`: protected upstream HTTPS origin, such as `https://mcp.example.com`.
- `OAUTH_PUBLIC_ORIGIN`: exact public Worker origin without a trailing slash, such as
  `https://mcp-api.example.com`.
- `OAUTH_CLIENT_ID`: client ID entered in Claude or ChatGPT.
- `OAUTH_ALLOWED_REDIRECT_URIS`: comma-separated exact client callback URLs.

Set these as encrypted Cloudflare secrets:

- `CF_SERVICE_TOKEN_ID`: Cloudflare Access service-token client ID.
- `CF_SERVICE_TOKEN_SECRET`: Cloudflare Access service-token secret.
- `OAUTH_CLIENT_SECRET`: confidential-client secret entered in Claude or ChatGPT.
- `OAUTH_SIGNING_SECRET`: 32+ character random token-signing secret.

The Access application protecting `MCP_ORIGIN` must use a **Service Auth** policy that admits the
configured Cloudflare service token. An identity-login policy would redirect the Worker and fail
the MCP request.

## Client Settings

- MCP server URL: `https://mcp-api.example.com/mcp`
- Authorization URL: `https://mcp-api.example.com/authorize`
- Token URL: `https://mcp-api.example.com/oauth/token`
- OAuth client ID: value of `OAUTH_CLIENT_ID`
- OAuth client secret: value of `OAUTH_CLIENT_SECRET`

The Worker supports `client_secret_basic` and `client_secret_post`. Dynamic registration is not
provided because the AI clients are configured manually with the confidential credentials.

## Security Model

- Authorization requests require an exact redirect URI, S256 PKCE, and the canonical MCP resource.
- Token requests require the confidential-client secret.
- Access tokens expire after one hour; refresh tokens expire after 30 days.
- Tokens are stateless and cannot be individually revoked. Rotate `OAUTH_SIGNING_SECRET` to revoke
  all issued tokens.
- Authorization codes are valid for five minutes. Their practical replay protection is the
  combination of PKCE and mandatory confidential-client authentication.
- Cloudflare Access credentials and client bearer tokens are not forwarded across redirects.

## Deployment

Use this folder as a Cloudflare Workers Builds project root. `keep_vars: true` preserves dashboard
variables and secrets during GitHub deployments. This project targets Cloudflare Workers, not Pages
Functions.