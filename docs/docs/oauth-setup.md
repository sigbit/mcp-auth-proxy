---
sidebar_position: 4
---

# OAuth Provider Setup

Configure OAuth providers to enable secure authentication for your MCP server.

## Google OAuth Setup

### 1. Google Cloud Console Configuration

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API:
   - Go to "APIs & Services" → "Library"
   - Search for "Google+ API" and enable it
4. Create OAuth consent screen:
   - Go to "APIs & Services" → "OAuth consent screen"
   - Choose "External" user type
   - Fill in required information

### 2. Create OAuth Credentials

1. Go to "APIs & Services" → "Credentials"
2. Click "Create credentials" → "OAuth client ID"
3. Choose "Web application"
4. Add authorized redirect URI: `{EXTERNAL_URL}/.auth/google/callback`
5. Note the Client ID and Client Secret

### 3. Configure MCP Auth Proxy

#### Allow specific users:

```bash
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --google-client-id "your-google-client-id" \
  --google-client-secret "your-google-client-secret" \
  --google-allowed-users "user1@example.com,user2@example.com" \
  -- your-mcp-command
```

#### Allow entire Google Workspaces:

```bash
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --google-client-id "your-google-client-id" \
  --google-client-secret "your-google-client-secret" \
  --google-allowed-workspaces "workspace1.com,workspace2.com" \
  -- your-mcp-command
```

## GitHub OAuth Setup

### 1. Register OAuth App

1. Go to [GitHub Developer Settings](https://github.com/settings/applications/new)
2. Fill in application details:
   - **Application name**: Your app name
   - **Homepage URL**: `https://{your-domain}`
   - **Authorization callback URL**: `{EXTERNAL_URL}/.auth/github/callback`
3. Note the Client ID and generate a Client Secret

### 2. Configure MCP Auth Proxy

```bash
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --github-client-id "your-github-client-id" \
  --github-client-secret "your-github-client-secret" \
  --github-allowed-users "username1,username2" \
  --github-allowed-orgs "org1,org2:team1" \
  -- your-mcp-command
```

## Generic OIDC Provider Setup

### Supported Providers

- Okta
- Auth0
- Azure AD (Microsoft Entra ID)
- Keycloak
- Any OpenID Connect compatible provider

### 1. Provider Configuration

1. Create a new application/client in your OIDC provider
2. Set redirect URI: `{EXTERNAL_URL}/.auth/oidc/callback`
3. Note the:
   - Configuration URL (usually `{issuer}/.well-known/openid-configuration`)
   - Client ID
   - Client Secret

### 2. Configure MCP Auth Proxy

#### Exact user matching:

```bash
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --oidc-configuration-url "https://your-provider.com/.well-known/openid-configuration" \
  --oidc-client-id "your-oidc-client-id" \
  --oidc-client-secret "your-oidc-client-secret" \
  --oidc-allowed-users "user1@example.com,user2@example.com" \
  -- your-mcp-command
```

#### Glob pattern matching:

```bash
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --oidc-configuration-url "https://your-provider.com/.well-known/openid-configuration" \
  --oidc-client-id "your-oidc-client-id" \
  --oidc-client-secret "your-oidc-client-secret" \
  --oidc-allowed-users-glob "*@example.com" \
  -- your-mcp-command
```

### Provider-Specific Examples

#### Okta

```bash
--oidc-configuration-url "https://your-domain.okta.com/.well-known/openid-configuration"
```

#### Auth0

```bash
--oidc-configuration-url "https://your-domain.auth0.com/.well-known/openid-configuration"
```

#### Azure AD

```bash
--oidc-configuration-url "https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration"
```

## Multiple Providers

You can enable multiple OAuth providers simultaneously:

```bash
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --password fallback-password \
  --google-client-id "google-client-id" \
  --google-client-secret "google-client-secret" \
  --google-allowed-users "user@gmail.com" \
  --github-client-id "github-client-id" \
  --github-client-secret "github-client-secret" \
  --github-allowed-users "githubuser" \
  -- your-mcp-command
```

## Environment Variables

All OAuth settings can be configured using environment variables:

```bash
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export GOOGLE_ALLOWED_USERS="user1@example.com,user2@example.com"
export GOOGLE_ALLOWED_WORKSPACES="workspace1.com,workspace2.com"

export GITHUB_CLIENT_ID="your-github-client-id"
export GITHUB_CLIENT_SECRET="your-github-client-secret"
export GITHUB_ALLOWED_USERS="username1,username2"
export GITHUB_ALLOWED_ORGS="org1,org2:team1"

export OIDC_CONFIGURATION_URL="https://provider.com/.well-known/openid-configuration"
export OIDC_CLIENT_ID="your-oidc-client-id"
export OIDC_CLIENT_SECRET="your-oidc-client-secret"
export OIDC_ALLOWED_USERS="user1@example.com,user2@example.com"
export OIDC_ALLOWED_USERS_GLOB="*@example.com"

./mcp-auth-proxy --external-url https://{your-domain} --tls-accept-tos -- your-mcp-command
```
