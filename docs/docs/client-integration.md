---
sidebar_position: 6
---

# MCP Client Integration

Learn how to connect various MCP clients to your authenticated MCP server.

## Supported Clients

MCP Auth Proxy has been verified to work with all major MCP clients:

| MCP Client        | Status | Notes                               |
| ----------------- | ------ | ----------------------------------- |
| Claude (Web)      | ✅     | Full compatibility                  |
| Claude (Desktop)  | ✅     | Full compatibility                  |
| Claude Code       | ✅     | Full compatibility                  |
| ChatGPT (Web)     | ✅     | Requires `search` and `fetch` tools |
| ChatGPT (Desktop) | ✅     | Requires `search` and `fetch` tools |
| GitHub Copilot    | ✅     | Full compatibility                  |
| Cursor            | ✅     | Full compatibility                  |

## Claude Integration

### Claude Desktop & Web

1. Go to Claude Settings → Connectors
2. Add custom connector
3. Enter URL: `https://{your-domain}/mcp`
4. You'll be redirected to authenticate

### Claude Code

Configure in `.mcp.json`:

```json
{
  "mcpServers": {
    "my-protected-server": {
      "url": "https://{your-domain}/mcp"
    }
  }
}
```

## ChatGPT Integration

### Prerequisites

ChatGPT requires your MCP server to implement `search` and `fetch` tools.

### Configuration

1. Go to ChatGPT Settings → Connectors
2. Create
3. Fill in the form:
   - **MCP Server URL**: `https://{your-domain}/mcp`
   - **Authentication**: OAuth
4. Complete authentication flow

## GitHub Copilot Integration

### VS Code Extension

Configure in `.vscode/mcp.json`:

```json
{
  "servers": {
    "my-protected-server": {
      "url": "https://{your-domain}/mcp",
      "type": "http"
    }
  },
  "inputs": []
}
```

## Cursor Integration

### Configuration

Configure in Cursor settings:

```json
{
  "mcpServers": {
    "my-protected-server": {
      "url": "https://{your-domain}/mcp"
    }
  }
}
```
