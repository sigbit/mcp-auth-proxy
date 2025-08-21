---
sidebar_position: 5
---

# Configuration Reference

Complete reference for all MCP Auth Proxy configuration options.

## Command Line Options

### Required Options

| Option           | Environment Variable | Default            | Description                |
| ---------------- | -------------------- | ------------------ | -------------------------- |
| `--external-url` | `EXTERNAL_URL`       | `http://localhost` | External URL for the proxy |

### TLS Options

| Option                | Environment Variable | Default                                          | Description                                    |
| --------------------- | -------------------- | ------------------------------------------------ | ---------------------------------------------- |
| `--auto-tls`          | `AUTO_TLS`           | `true`                                           | Automatically detect TLS host from externalURL |
| `--tls-accept-tos`    | `TLS_ACCEPT_TOS`     | `false`                                          | Accept TLS terms of service                    |
| `--tls-directory-url` | `TLS_DIRECTORY_URL`  | `https://acme-v02.api.letsencrypt.org/directory` | ACME directory URL for TLS certificates        |
| `--tls-host`          | `TLS_HOST`           | -                                                | Host name for TLS                              |

### Authentication Options

#### Password Authentication

| Option            | Environment Variable | Default | Description                                                         |
| ----------------- | -------------------- | ------- | ------------------------------------------------------------------- |
| `--password`      | `PASSWORD`           | -       | Plain text password for authentication (will be hashed with bcrypt) |
| `--password-hash` | `PASSWORD_HASH`      | -       | Bcrypt hash of password for authentication                          |

#### Google OAuth

| Option                   | Environment Variable   | Default | Description                                           |
| ------------------------ | ---------------------- | ------- | ----------------------------------------------------- |
| `--google-client-id`     | `GOOGLE_CLIENT_ID`     | -       | Google OAuth client ID                                |
| `--google-client-secret` | `GOOGLE_CLIENT_SECRET` | -       | Google OAuth client secret                            |
| `--google-allowed-users` | `GOOGLE_ALLOWED_USERS` | -       | Comma-separated list of allowed Google users (emails) |

#### GitHub OAuth

| Option                   | Environment Variable   | Default | Description                                              |
| ------------------------ | ---------------------- | ------- | -------------------------------------------------------- |
| `--github-client-id`     | `GITHUB_CLIENT_ID`     | -       | GitHub OAuth client ID                                   |
| `--github-client-secret` | `GITHUB_CLIENT_SECRET` | -       | GitHub OAuth client secret                               |
| `--github-allowed-users` | `GITHUB_ALLOWED_USERS` | -       | Comma-separated list of allowed GitHub users (usernames) |

#### Generic OIDC

| Option                     | Environment Variable     | Default                | Description                                                 |
| -------------------------- | ------------------------ | ---------------------- | ----------------------------------------------------------- |
| `--oidc-configuration-url` | `OIDC_CONFIGURATION_URL` | -                      | OIDC configuration URL                                      |
| `--oidc-client-id`         | `OIDC_CLIENT_ID`         | -                      | OIDC client ID                                              |
| `--oidc-client-secret`     | `OIDC_CLIENT_SECRET`     | -                      | OIDC client secret                                          |
| `--oidc-allowed-users`     | `OIDC_ALLOWED_USERS`     | -                      | Comma-separated list of allowed OIDC users                  |
| `--oidc-provider-name`     | `OIDC_PROVIDER_NAME`     | `OIDC`                 | Display name for OIDC provider                              |
| `--oidc-scopes`            | `OIDC_SCOPES`            | `openid,profile,email` | Comma-separated list of OIDC scopes                         |
| `--oidc-user-id-field`     | `OIDC_USER_ID_FIELD`     | `/email`               | JSON pointer to user ID field in userinfo endpoint response |

### Server Options

| Option         | Environment Variable | Default  | Description                  |
| -------------- | -------------------- | -------- | ---------------------------- |
| `--listen`     | `LISTEN`             | `:80`    | Address to listen on         |
| `--listen-tls` | `LISTEN_TLS`         | `:443`   | Address to listen on for TLS |
| `--data`       | `DATA`               | `./data` | Path to the data directory   |

### Proxy Options

| Option                 | Environment Variable | Default | Description                                                                                           |
| ---------------------- | -------------------- | ------- | ----------------------------------------------------------------------------------------------------- |
| `--proxy-bearer-token` | `PROXY_BEARER_TOKEN` | -       | Bearer token to add to Authorization header when proxying requests                                    |
| `--proxy-headers`      | `PROXY_HEADERS`      | -       | Comma-separated list of headers to add when proxying requests (format: Header1:Value1,Header2:Value2) |

## Environment Variables

All configuration options can be set via environment variables:

```bash
# Core settings
export EXTERNAL_URL="https://{your-domain}"
export AUTO_TLS="true"
export TLS_ACCEPT_TOS="true"
export DATA="./data"

# Authentication
export PASSWORD="your-secure-password"

# Google OAuth
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export GOOGLE_ALLOWED_USERS="user1@example.com,user2@example.com"

# GitHub OAuth
export GITHUB_CLIENT_ID="your-github-client-id"
export GITHUB_CLIENT_SECRET="your-github-client-secret"
export GITHUB_ALLOWED_USERS="username1,username2"

# OIDC
export OIDC_CONFIGURATION_URL="https://provider.com/.well-known/openid-configuration"
export OIDC_CLIENT_ID="your-oidc-client-id"
export OIDC_CLIENT_SECRET="your-oidc-client-secret"
export OIDC_ALLOWED_USERS="user1@example.com,user2@example.com"

./mcp-auth-proxy -- your-mcp-command
```

## Docker Configuration

### Docker Compose

```yaml
version: "3.8"
services:
  mcp-auth-proxy:
    image: ghcr.io/sigbit/mcp-auth-proxy:latest
    ports:
      - "80:80"
      - "443:443"
    environment:
      - EXTERNAL_URL=https://{your-domain}
      - TLS_ACCEPT_TOS=true
      - PASSWORD=your-secure-password
      - GOOGLE_CLIENT_ID=your-google-client-id
      - GOOGLE_CLIENT_SECRET=your-google-client-secret
      - GOOGLE_ALLOWED_USERS=user1@example.com,user2@example.com
    volumes:
      - ./data:/data
    command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "./"]
    restart: unless-stopped
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-auth-proxy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mcp-auth-proxy
  template:
    metadata:
      labels:
        app: mcp-auth-proxy
    spec:
      containers:
        - name: mcp-auth-proxy
          image: ghcr.io/sigbit/mcp-auth-proxy:latest
          ports:
            - containerPort: 80
          env:
            - name: EXTERNAL_URL
              value: "https://{your-domain}"
            - name: AUTO_TLS
              value: "false"
            - name: PASSWORD
              valueFrom:
                secretKeyRef:
                  name: mcp-auth-proxy-secrets
                  key: password
          volumeMounts:
            - name: data
              mountPath: /data
          args: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "./"]
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: mcp-auth-proxy-data
---
apiVersion: v1
kind: Service
metadata:
  name: mcp-auth-proxy
spec:
  selector:
    app: mcp-auth-proxy
  ports:
    - port: 80
      targetPort: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mcp-auth-proxy
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
spec:
  tls:
    - hosts:
        - { your-domain }
      secretName: mcp-auth-proxy-tls
  rules:
    - host: { your-domain }
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: mcp-auth-proxy
                port:
                  number: 80
```
