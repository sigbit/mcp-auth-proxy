---
sidebar_position: 7
---

# Configuration Reference

Complete reference for all MCP Auth Proxy configuration options.

## Command Line Options

### Required Options

| Option           | Environment Variable | Default            | Description                |
| ---------------- | -------------------- | ------------------ | -------------------------- |
| `--external-url` | `EXTERNAL_URL`       | `http://localhost` | External URL for the proxy |

### TLS Options

| Option                | Environment Variable | Default                                          | Description                                           |
| --------------------- | -------------------- | ------------------------------------------------ | ----------------------------------------------------- |
| `--no-auto-tls`       | `NO_AUTO_TLS`        | `false`                                          | Disable automatic TLS host detection from externalURL |
| `--tls-accept-tos`    | `TLS_ACCEPT_TOS`     | `false`                                          | Accept TLS terms of service                           |
| `--tls-directory-url` | `TLS_DIRECTORY_URL`  | `https://acme-v02.api.letsencrypt.org/directory` | ACME directory URL for TLS certificates               |
| `--tls-host`          | `TLS_HOST`           | -                                                | Host name for TLS                                     |

### Authentication Options

#### Password Authentication

| Option            | Environment Variable | Default | Description                                                         |
| ----------------- | -------------------- | ------- | ------------------------------------------------------------------- |
| `--password`      | `PASSWORD`           | -       | Plain text password for authentication (will be hashed with bcrypt) |
| `--password-hash` | `PASSWORD_HASH`      | -       | Bcrypt hash of password for authentication                          |

#### Google OAuth

| Option                        | Environment Variable        | Default | Description                                           |
| ----------------------------- | --------------------------- | ------- | ----------------------------------------------------- |
| `--google-client-id`          | `GOOGLE_CLIENT_ID`          | -       | Google OAuth client ID                                |
| `--google-client-secret`      | `GOOGLE_CLIENT_SECRET`      | -       | Google OAuth client secret                            |
| `--google-allowed-users`      | `GOOGLE_ALLOWED_USERS`      | -       | Comma-separated list of allowed Google users (emails) |
| `--google-allowed-workspaces` | `GOOGLE_ALLOWED_WORKSPACES` | -       | Comma-separated list of allowed Google workspaces     |

#### GitHub OAuth

| Option                   | Environment Variable   | Default | Description                                                                                                                      |
| ------------------------ | ---------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `--github-client-id`     | `GITHUB_CLIENT_ID`     | -       | GitHub OAuth client ID                                                                                                           |
| `--github-client-secret` | `GITHUB_CLIENT_SECRET` | -       | GitHub OAuth client secret                                                                                                       |
| `--github-allowed-users` | `GITHUB_ALLOWED_USERS` | -       | Comma-separated list of allowed GitHub users (usernames)                                                                         |
| `--github-allowed-orgs`  | `GITHUB_ALLOWED_ORGS`  | -       | Comma-separated list of allowed GitHub organizations. You can also restrict access to specific teams using the format `Org:Team` |

#### Generic OIDC

| Option                      | Environment Variable      | Default                | Description                                                  |
| --------------------------- | ------------------------- | ---------------------- | ------------------------------------------------------------ |
| `--oidc-configuration-url`  | `OIDC_CONFIGURATION_URL`  | -                      | OIDC configuration URL                                       |
| `--oidc-client-id`          | `OIDC_CLIENT_ID`          | -                      | OIDC client ID                                               |
| `--oidc-client-secret`      | `OIDC_CLIENT_SECRET`      | -                      | OIDC client secret                                           |
| `--oidc-allowed-users`      | `OIDC_ALLOWED_USERS`      | -                      | Comma-separated list of allowed OIDC users (exact match)     |
| `--oidc-allowed-users-glob` | `OIDC_ALLOWED_USERS_GLOB` | -                      | Comma-separated list of glob patterns for allowed OIDC users |
| `--oidc-provider-name`      | `OIDC_PROVIDER_NAME`      | `OIDC`                 | Display name for OIDC provider                               |
| `--oidc-scopes`             | `OIDC_SCOPES`             | `openid,profile,email` | Comma-separated list of OIDC scopes                          |
| `--oidc-user-id-field`      | `OIDC_USER_ID_FIELD`      | `/email`               | JSON pointer to user ID field in userinfo endpoint response  |

##### OIDC User Matching

You can use both exact matching and glob patterns for OIDC user authorization:

- **Exact matching** (`--oidc-allowed-users`): Users must match exactly
- **Glob patterns** (`--oidc-allowed-users-glob`): Users are matched against [glob patterns](https://github.com/gobwas/glob)

**Examples:**

```bash
# Exact matching
--oidc-allowed-users "user1@example.com,admin@company.org"

# Glob patterns - allow all users from example.com
--oidc-allowed-users-glob "*@example.com"

# Combined exact and glob matching
--oidc-allowed-users "specific@user.com" \
--oidc-allowed-users-glob "*@example.com"
```

### Server Options

| Option         | Environment Variable | Default  | Description                  |
| -------------- | -------------------- | -------- | ---------------------------- |
| `--listen`     | `LISTEN`             | `:80`    | Address to listen on         |
| `--tls-listen` | `TLS_LISTEN`         | `:443`   | Address to listen on for TLS |
| `--data-path`  | `DATA_PATH`          | `./data` | Path to the data directory   |

### Proxy Options

| Option                 | Environment Variable | Default | Description                                                                                           |
| ---------------------- | -------------------- | ------- | ----------------------------------------------------------------------------------------------------- |
| `--proxy-bearer-token` | `PROXY_BEARER_TOKEN` | -       | Bearer token to add to Authorization header when proxying requests                                    |
| `--proxy-headers`      | `PROXY_HEADERS`      | -       | Comma-separated list of headers to add when proxying requests (format: Header1:Value1,Header2:Value2) |
| `--trusted-proxies`    | `TRUSTED_PROXIES`    | -       | Comma-separated list of trusted proxies (IP addresses or CIDR ranges)                                 |

For practical configuration examples including environment variables, Docker Compose, and Kubernetes deployments, see the [Configuration Examples](./examples.md) page.
