# MCP Auth Proxy

![Secure your MCP server with OAuth 2.1 — in a minute](./mcp-auth-proxy.svg)

If this project saves you time, please give it a star — it really helps visibility.

## Quickstart

> Domain binding & 80/443 must be accessible from outside.

### Binary

Download binary from [release](https://github.com/sigbit/mcp-auth-proxy/releases) page.

If you use stdio transport

```sh
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --password changeme \
  -- npx -y @modelcontextprotocol/server-filesystem /
```

If you use sse/http transport

```sh
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --password changeme \
  http://localhost:8080
```

This will automatically obtain and manage Let's Encrypt TLS certificates for your domain.

```json
{
  "mcpServers": {
    "mcp": {
      "type": "http",
      "url": "https://{your-domain}/mcp"
    }
  }
}
```

### Docker


If you use stdio transport

```
docker run --rm -p 80:80 -p 443:443 \
  -e EXTERNAL_URL=https://{your-domain} \
  -e TLS_ACCEPT_TOS=1 \
  -e PASSWORD=changeme \
  -v ./data:/data \
  ghcr.io/sigbit/mcp-auth-proxy:latest \
  -- npx -y @modelcontextprotocol/server-filesystem /
```

If you use sse/http transport

```
docker run --rm --net=host \
  -e EXTERNAL_URL=https://{your-domain} \
  -e TLS_ACCEPT_TOS=1 \
  -e PASSWORD=changeme \
  -v ./data:/data \
  ghcr.io/sigbit/mcp-auth-proxy:latest \
  http://localhost:8080
```

This will automatically obtain and manage Let's Encrypt TLS certificates for your domain.

```json
{
  "mcpServers": {
    "mcp": {
      "type": "http",
      "url": "https://{your-domain}/mcp"
    }
  }
}
```


## Overview

MCP Auth Proxy is a secure OAuth 2.1 authentication proxy for Model Context Protocol (MCP) servers. MCP servers are expected to support not only standard OAuth 2.1 flows but also Dynamic Client support (e.g., dynamic client registration) and authentication-related .well-known metadata. On top of that, different MCP clients handle tokens differently, which makes implementation tricky.

MCP Auth Proxy sits in front of your MCP services and enforces sign-in with OAuth providers (such as Google or GitHub or OIDC) or password before users can access protected MCP resources.

## Note

For a simpler approach to publish local MCP servers over OAuth, consider [MCP Warp](https://github.com/sigbit/mcp-warp), which provides an OAuth Proxy + ngrok-like service. We highly recommend considering this option as well.

## 🔧 Configuration

### Environment Variables

| Variable                 | Required | Description                                                                                           | Default                                          |
| ------------------------ | -------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| `LISTEN`                 | No       | Server listen address                                                                                 | `:80`                                            |
| `TLS_LISTEN`             | No       | Address to listen on for TLS                                                                          | `:443`                                           |
| `AUTO_TLS`               | No       | Automatically setup TLS certificates from externalURL                                                 | `true`                                           |
| `TLS_HOST`               | No       | Host name for automatic TLS certificate                                                               | -                                                |
| `TLS_DIRECTORY_URL`      | No       | ACME directory URL for TLS certificates                                                               | `https://acme-v02.api.letsencrypt.org/directory` |
| `TLS_ACCEPT_TOS`         | No       | Accept TLS terms of service                                                                           | `false`                                          |
| `DATA_PATH`              | No       | Data directory path                                                                                   | `./data`                                         |
| `EXTERNAL_URL`           | No       | External URL for OAuth callbacks                                                                      | `http://localhost`                               |
| `GOOGLE_CLIENT_ID`       | No       | Google OAuth client ID                                                                                | -                                                |
| `GOOGLE_CLIENT_SECRET`   | No       | Google OAuth client secret                                                                            | -                                                |
| `GOOGLE_ALLOWED_USERS`   | No       | Comma-separated list of allowed Google emails                                                         | -                                                |
| `GITHUB_CLIENT_ID`       | No       | GitHub OAuth client ID                                                                                | -                                                |
| `GITHUB_CLIENT_SECRET`   | No       | GitHub OAuth client secret                                                                            | -                                                |
| `GITHUB_ALLOWED_USERS`   | No       | Comma-separated list of allowed GitHub usernames                                                      | -                                                |
| `OIDC_CONFIGURATION_URL` | No       | OIDC configuration URL                                                                                | -                                                |
| `OIDC_CLIENT_ID`         | No       | OIDC client ID                                                                                        | -                                                |
| `OIDC_CLIENT_SECRET`     | No       | OIDC client secret                                                                                    | -                                                |
| `OIDC_SCOPES`            | No       | Comma-separated list of OIDC scopes                                                                   | `openid,profile,email`                           |
| `OIDC_USER_ID_FIELD`     | No       | JSON pointer to user ID field in userinfo endpoint response                                           | `/email`                                         |
| `OIDC_PROVIDER_NAME`     | No       | Display name for OIDC provider                                                                        | `OIDC`                                           |
| `OIDC_ALLOWED_USERS`     | No       | Comma-separated list of allowed OIDC users                                                            | -                                                |
| `PASSWORD`               | No       | Plain text password (will be hashed with bcrypt)                                                      | -                                                |
| `PASSWORD_HASH`          | No       | Bcrypt hash of password for authentication                                                            | -                                                |
| `PROXY_BEARER_TOKEN`     | No       | Bearer token to add to Authorization header when proxying requests                                    | -                                                |
| `PROXY_HEADERS`          | No       | Comma-separated list of headers to add when proxying requests (format: Header1:Value1,Header2:Value2) | -                                                |
| `MODE`                   | No       | Set to `debug` for development mode                                                                   | `production`                                     |

### OAuth Provider Setup

#### Google OAuth Setup
1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URI: `{EXTERNAL_URL}/.auth/google/callback`

#### GitHub OAuth Setup
1. Go to the [Register new GitHub App](https://github.com/settings/apps/new)
2. Set Authorization callback URL: `{EXTERNAL_URL}/.auth/github/callback`

#### OIDC Provider Setup
1. Configure your OIDC provider (e.g., Keycloak, Auth0, Azure AD, etc.)
2. Create a new client application
3. Set redirect URI: `{EXTERNAL_URL}/.auth/oidc/callback`
4. Note the configuration URL (usually issuer URL + /.well-known/openid-configuration), client ID, and client secret
5. Configure the userinfo endpoint to return user identification field (default: email)

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
  http://localhost:8080
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
  http://localhost:8080
```

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
