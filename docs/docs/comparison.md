---
sidebar_position: 2
---

# Why not MCP Gateway?

mcp-auth-proxy: **A lightweight proxy that adds authentication to any MCP server** (optional stdio→HTTP(S) conversion)  
MCP Gateway: **A hub to orchestrate multiple MCP servers** (aggregation, catalog integration)

## When to choose `mcp-auth-proxy`

- **You just need to add auth to one or a few MCPs** (enforce OAuth/OIDC/password-only)
- **Catalog integration and aggregation aren’t needed** (either self-hosted or independently managed MCP.)

## When to choose MCP Gateway

- **You need to manage multiple MCPs centrally** (aggregation, policies/permissions, auditing, centralized logging)
- **You want catalog integration and aggregation**

_Note_: They are not mutually exclusive. You can **put `mcp-auth-proxy` in front of a Gateway's public endpoint to enforce authentication** if the Gateway itself doesn't handle it.

**TL;DR:** Orchestrate many → Gateway / Expose safely & quickly → mcp-auth-proxy
