---
sidebar_position: 1
---

# Introduction

MCP Auth Proxy is a drop-in OAuth 2.1/OIDC gateway for MCP (Model Context Protocol) servers that adds authentication without requiring any code changes to your existing MCP servers.

## What is MCP Auth Proxy?

MCP Auth Proxy sits between MCP clients (like Claude, ChatGPT, GitHub Copilot) and your MCP servers, providing secure authentication through popular OAuth providers.

### Key Features

- **Zero-code integration**: Put it in front of any MCP server without modifications
- **Multiple OAuth providers**: Google, GitHub, or any OIDC provider (Okta, Auth0, Azure AD, Keycloak)
- **Transport flexibility**: Supports stdio, SSE, and HTTP transports
- **Client compatibility**: Verified across major MCP clients with quirk smoothing
- **Secure publishing**: Safely expose local MCP servers to the internet

### How It Works

1. **Client Connection**: MCP clients connect to the proxy instead of directly to your server
2. **Authentication**: Users authenticate through your chosen OAuth provider
3. **Authorization**: Access is granted based on configured user allowlists
4. **Proxying**: Authenticated requests are forwarded to your MCP server

## Next Steps

- [Quick Start Guide](./quickstart.md) - Get up and running in minutes
- [OAuth Setup](./oauth-setup.md) - Configure secure authentication providers
- [Client Integration](./client-integration.md) - Connect with MCP clients
