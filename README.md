# MCP Auth Proxy

![Secure your MCP server with OAuth 2.1 — in a minute](./mcp-auth-proxy.svg)

> If you found value here, please consider starring.

## Overview

- **Drop-in OAuth 2.1/OIDC gateway for MCP servers — put it in front, no code changes.**
- **Your IdP, your choice**: Google, GitHub, or any OIDC provider — e.g. Okta, Auth0, Azure AD, Keycloak — plus optional password with allow-list.
- **Publish local stdio MCP servers safely**: bridge to a public streamable HTTP endpoint (/mcp) with automatic TLS (ACME/Let’s Encrypt).
- **Verified across major MCP clients**: Claude, Claude Code, ChatGPT, GitHub Copilot, Cursor, etc. — the proxy smooths client-specific quirks for consistent auth.

## Quickstart

> Domain binding & 80/443 must be accessible from outside.

Download binary from [release](https://github.com/sigbit/mcp-auth-proxy/releases) page.

If you use stdio transport

```sh
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --password changeme \
  -- npx -y @modelcontextprotocol/server-filesystem /
```

That's it! Your streamable HTTP endpoint is now available at `https://{your-domain}/mcp`.  
To proxy SSE/streamable HTTP transport, specify a URL; to use the stdio transport, specify a command.

(Listen on 80/443 and automatically set up certificates, but use the no-auto-tls option if not needed.)

## Verified MCP Client

| MCP Client        | Status | Notes                                             |
| ----------------- | ------ | ------------------------------------------------- |
| Claude - Web      | ✅      |                                                   |
| Claude - Desktop  | ✅      |                                                   |
| Claude Code       | ✅      |                                                   |
| ChatGPT - Web     | ✅      | Need to implement `search` and `fetch` tools.(*1) |
| ChatGPT - Desktop | ✅      | Need to implement `search` and `fetch` tools.(*1) |
| GitHub Copilot    | ✅      |                                                   |
| Cursor            | ✅      |                                                   |

- *1: https://platform.openai.com/docs/mcp

## 🚀 Usage

### Method 1: Download Binary

Download the latest binary from [releases](https://github.com/sigbit/mcp-auth-proxy/releases) and run with command line options:

```bash
./mcp-auth-proxy \
  --external-url "https://{your-domain}" \
  --tls-accept-tos \
  --password "changeme" \
  --google-client-id "your-google-client-id" \
  --google-client-secret "your-google-client-secret" \
  --google-allowed-users "user1@example.com,user2@example.com" \
  --github-client-id "your-github-client-id" \
  --github-client-secret "your-github-client-secret" \
  --github-allowed-users "username1,username2" \
  --oidc-configuration-url "https://your-oidc-provider.com/.well-known/openid-configuration" \
  --oidc-client-id "your-oidc-client-id" \
  --oidc-client-secret "your-oidc-client-secret" \
  --oidc-allowed-users "user1@example.com,user2@example.com" \
  http://localhost:8080 # or execute command (for stdio transport)
```

### Method 2: Docker

```bash
docker run --rm --net=host \
  -e EXTERNAL_URL=https://{your-domain} \
  -e TLS_ACCEPT_TOS=1 \
  -e PASSWORD=changeme \
  -e GOOGLE_CLIENT_ID="your-google-client-id" \
  -e GOOGLE_CLIENT_SECRET="your-google-client-secret" \
  -e GOOGLE_ALLOWED_USERS="user1@example.com,user2@example.com" \
  -e GITHUB_CLIENT_ID="your-github-client-id" \
  -e GITHUB_CLIENT_SECRET="your-github-client-secret" \
  -e GITHUB_ALLOWED_USERS="username1,username2" \
  -e OIDC_CONFIGURATION_URL="https://your-oidc-provider.com/.well-known/openid-configuration" \
  -e OIDC_CLIENT_ID="your-oidc-client-id" \
  -e OIDC_CLIENT_SECRET="your-oidc-client-secret" \
  -e OIDC_ALLOWED_USERS="user1@example.com,user2@example.com" \
  -v ./data:/data \
  ghcr.io/sigbit/mcp-auth-proxy:latest \
  http://localhost:8080 # or execute command (for stdio transport)
```

## 🔧 Configuration

### Provider Setup

#### Google OAuth Setup
1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Create OAuth consent screen
4. Credentials → Create credentials → OAuth client ID（Web application）
5. Add authorized redirect URI: `{EXTERNAL_URL}/.auth/google/callback`

#### GitHub OAuth Setup
1. Go to the [Register new OAuth App](https://github.com/settings/applications/new)
2. Set Authorization callback URL: `{EXTERNAL_URL}/.auth/github/callback`

#### OIDC Provider Setup
1. Configure your OIDC provider (e.g., Keycloak, Auth0, Azure AD, etc.)
2. Create a new client application
3. Set redirect URI: `{EXTERNAL_URL}/.auth/oidc/callback`
4. Note the configuration URL (usually issuer URL + /.well-known/openid-configuration), client ID, and client secret
5. Configure the userinfo endpoint to return user identification field (default: email)

## Note

For a simpler approach to publish local MCP servers over OAuth, consider [MCP Warp](https://github.com/sigbit/mcp-warp), which provides an OAuth Proxy + ngrok-like service. We highly recommend considering this option as well.

## 🤝 Contributing

For developer guidelines, contribution instructions, and commit message conventions, please see [CONTRIBUTING.md](./CONTRIBUTING.md).

### AI Development Environment Setup

You can link CONTRIBUTING.md to your preferred AI development environment for better integration:

```bash
# For Claude Code
ln -s CONTRIBUTING.md CLAUDE.md

# For Gemini
ln -s CONTRIBUTING.md GEMINI.md

# For GitHub Copilot
mkdir -p .github
ln -s CONTRIBUTING.md .github/copilot-instructions.md
```

This allows your AI assistant to access the contribution guidelines regardless of which development environment you prefer to use.
