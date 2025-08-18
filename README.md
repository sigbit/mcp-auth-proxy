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

MCP Auth Proxy sits in front of your MCP services and enforces sign-in with OAuth providers (such as Google or GitHub) or password before users can access protected MCP resources.

## Note

For a simpler approach to publish local MCP servers over OAuth, consider [MCP Warp](https://github.com/sigbit/mcp-warp), which provides an OAuth Proxy + ngrok-like service. We highly recommend considering this option as well.

## 🔧 Configuration

### Environment Variables

| Variable               | Required | Description                                                                                           | Default                                          |
| ---------------------- | -------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| `LISTEN`               | No       | Server listen address                                                                                 | `:80`                                            |
| `TLS_LISTEN`           | No       | Address to listen on for TLS                                                                          | `:443`                                           |
| `TLS_HOST`             | No       | Host name for automatic TLS certificate                                                               | -                                                |
| `TLS_HOST_AUTO_DETECT` | No       | Automatically detect TLS host from externalURL                                                        | `true`                                           |
| `TLS_DIRECTORY_URL`    | No       | ACME directory URL for TLS certificates                                                               | `https://acme-v02.api.letsencrypt.org/directory` |
| `TLS_ACCEPT_TOS`       | No       | Accept TLS terms of service                                                                           | `false`                                          |
| `DATA_PATH`            | No       | Data directory path                                                                                   | `./data`                                         |
| `EXTERNAL_URL`         | No       | External URL for OAuth callbacks                                                                      | `http://localhost`                               |
| `GOOGLE_CLIENT_ID`     | No       | Google OAuth client ID                                                                                | -                                                |
| `GOOGLE_CLIENT_SECRET` | No       | Google OAuth client secret                                                                            | -                                                |
| `GOOGLE_ALLOWED_USERS` | No       | Comma-separated list of allowed Google emails                                                         | -                                                |
| `GITHUB_CLIENT_ID`     | No       | GitHub OAuth client ID                                                                                | -                                                |
| `GITHUB_CLIENT_SECRET` | No       | GitHub OAuth client secret                                                                            | -                                                |
| `GITHUB_ALLOWED_USERS` | No       | Comma-separated list of allowed GitHub usernames                                                      | -                                                |
| `PASSWORD`             | No       | Plain text password (will be hashed with bcrypt)                                                      | -                                                |
| `PASSWORD_HASH`        | No       | Bcrypt hash of password for authentication                                                            | -                                                |
| `PROXY_BEARER_TOKEN`   | No       | Bearer token to add to Authorization header when proxying requests                                    | -                                                |
| `PROXY_HEADERS`        | No       | Comma-separated list of headers to add when proxying requests (format: Header1:Value1,Header2:Value2) | -                                                |
| `MODE`                 | No       | Set to `debug` for development mode                                                                   | `production`                                     |

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
  -v ./data:/data \
  ghcr.io/sigbit/mcp-auth-proxy:latest \
  http://localhost:8080
```

## 👨‍💻 For Developers

### Commit Message Guidelines

This project follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification for commit messages. This helps with automated versioning, changelog generation, and makes the commit history more readable.

#### Types

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation only changes
- **style**: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **perf**: A code change that improves performance
- **test**: Adding missing tests or correcting existing tests
- **build**: Changes that affect the build system or external dependencies
- **ci**: Changes to our CI configuration files and scripts
- **chore**: Other changes that don't modify src or test files
- **revert**: Reverts a previous commit

#### Examples

```
feat: add GitHub OAuth provider support
fix: resolve token expiration handling
docs: update OAuth setup instructions
refactor: simplify authentication middleware
ci: add automated release workflow
```

#### Breaking Changes

Breaking changes should be indicated by a `!` after the type/scope:

```
feat!: change authentication API to support multiple providers
```
