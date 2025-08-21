---
sidebar_position: 2
---

# Quick Start

Get MCP Auth Proxy running in minutes with this step-by-step guide.

## Prerequisites

- A domain name pointing to your server
- Port 80/443 accessible from the internet
- An MCP server to protect (or use our example)

## Installation

### Method 1: Binary Download

Download the latest binary from the [releases page](https://github.com/sigbit/mcp-auth-proxy/releases):

```bash
# Download and make executable
wget https://github.com/sigbit/mcp-auth-proxy/releases/latest/download/mcp-auth-proxy-linux-amd64
chmod +x mcp-auth-proxy-linux-amd64
mv mcp-auth-proxy-linux-amd64 mcp-auth-proxy
```

### Method 2: Docker

```bash
docker pull ghcr.io/sigbit/mcp-auth-proxy:latest
```

## Basic Usage

### With Password Authentication

The simplest setup uses password authentication:

```bash
./mcp-auth-proxy \
  --external-url https://{your-domain} \
  --tls-accept-tos \
  --password your-secure-password \
  -- npx -y @modelcontextprotocol/server-filesystem ./
```

### With Docker

```bash
docker run --rm --net=host \
  -e EXTERNAL_URL=https://{your-domain} \
  -e TLS_ACCEPT_TOS=1 \
  -e PASSWORD=your-secure-password \
  -v ./data:/data \
  ghcr.io/sigbit/mcp-auth-proxy:latest \
  npx -y @modelcontextprotocol/server-filesystem ./
```

## Configuration Options

### Transport Types

#### stdio Transport

For command-based MCP servers (stdio transport is automatically converted to HTTP and served at `/mcp`):

```bash
./mcp-auth-proxy [options] -- your-mcp-command [args]
```

#### HTTP/SSE Transport

For URL-based MCP servers:

```bash
./mcp-auth-proxy [options] http://localhost:8080
```

### TLS Configuration

MCP Auth Proxy automatically handles HTTPS certificates:

- `--tls-accept-tos`: Accept Let's Encrypt terms of service
- `--no-auto-tls`: Disable automatic TLS (use with TLS reverse proxy)

## Accessing Your Server

Once running, your MCP server will be available at different endpoints depending on the transport type:

### stdio Transport (when command is specified)

- **MCP Endpoint**: `https://{your-domain}/mcp`

### SSE/HTTP Transport (when URL is specified)

- **MCP Endpoint**: Uses the backend's original path (no conversion performed)

## Next Steps

- [Configure OAuth providers](./oauth-setup.md) for enhanced security
- [Integrate with MCP clients](./client-integration.md)
