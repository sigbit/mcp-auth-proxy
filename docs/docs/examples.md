---
sidebar_position: 5
---

# Configuration Examples

This page provides practical configuration examples for different deployment scenarios.

For detailed information about each configuration option, see the [Configuration Reference](./configuration.md).

## Binary Usage

```bash
./mcp-auth-proxy \
  --external-url "https://your-domain.com" \
  --password "your-secure-password" \
  --tls-accept-tos \
  -- npx -y @modelcontextprotocol/server-filesystem ./
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
      - GOOGLE_ALLOWED_WORKSPACES=workspace1.com,workspace2.com
      - GITHUB_CLIENT_ID=your-github-client-id
      - GITHUB_CLIENT_SECRET=your-github-client-secret
      - GITHUB_ALLOWED_USERS=username1,username2
      - GITHUB_ALLOWED_ORGS=org1,org2:team1
      - OIDC_CONFIGURATION_URL=https://your-oidc-provider/.well-known/openid_configuration
      - OIDC_CLIENT_ID=your-oidc-client-id
      - OIDC_CLIENT_SECRET=your-oidc-client-secret
      - OIDC_ALLOWED_USERS=specific@user.com
      - OIDC_ALLOWED_USERS_GLOB=*@example.com
      - TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
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
            - name: NO_AUTO_TLS
              value: "true"
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
