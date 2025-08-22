---
sidebar_position: 2
---

# Why not MCP Gateway?

MCP Gateway: **A hub for operating multiple MCP servers together** (container isolation, catalog integration)  
mcp-auth-proxy: **A lightweight proxy that adds authentication in front of any MCP server** (+ stdio→HTTP(S) conversion, optional)

## When to choose `mcp-auth-proxy`

- **You just want to add auth to one or a few MCPs** (enforce OAuth/OIDC/password with zero changes to the server)
- **Container operations and catalog integration aren’t needed** (ideal for small setups, testing/PoC, or one-off exposure)

## When to choose MCP Gateway

- **Operating many MCPs at organizational scale** (provisioning, policy/permissions, audit, centralized logs)
- **You want operations features** like container isolation and catalog integration

_Note_: They are not mutually exclusive. You can **put `mcp-auth-proxy` in front of a Gateway's public endpoint to enforce authentication** if the Gateway itself doesn't handle it.

**TL;DR:** Orchestrate many → Gateway / Expose safely & quickly → mcp-auth-proxy
