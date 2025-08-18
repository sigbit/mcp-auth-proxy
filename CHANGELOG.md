# Changelog

## [1.2.1](https://github.com/sigbit/mcp-auth-proxy/compare/v1.2.0...v1.2.1) (2025-08-18)


### Bug Fixes

* improve proxy header handling and remove existing Authorization header ([#25](https://github.com/sigbit/mcp-auth-proxy/issues/25)) ([409b10e](https://github.com/sigbit/mcp-auth-proxy/commit/409b10e231238a332ff2efae828076ca6f8b98a2))

## [1.2.0](https://github.com/sigbit/mcp-auth-proxy/compare/v1.1.1...v1.2.0) (2025-08-18)


### Features

* add automatic TLS host detection and improve server lifecycle management ([#21](https://github.com/sigbit/mcp-auth-proxy/issues/21)) ([dc3c058](https://github.com/sigbit/mcp-auth-proxy/commit/dc3c05846ce3fb4460f0f82d8c8cf572be7f28ab))
* add support for stdio MCP servers ([#19](https://github.com/sigbit/mcp-auth-proxy/issues/19)) ([b159d26](https://github.com/sigbit/mcp-auth-proxy/commit/b159d26866c1e362dc074f11277e04c12b640a0e))


### Bug Fixes

* handle stderr properly in stdio MCP server execution ([#23](https://github.com/sigbit/mcp-auth-proxy/issues/23)) ([f972958](https://github.com/sigbit/mcp-auth-proxy/commit/f972958904cf55e3af637466e3c323e2c799260e))
* improve backend lifecycle management and error handling ([#24](https://github.com/sigbit/mcp-auth-proxy/issues/24)) ([4b5e828](https://github.com/sigbit/mcp-auth-proxy/commit/4b5e828cc9932fa41def32385d4fc20456ee588f))

## [1.1.1](https://github.com/sigbit/mcp-auth-proxy/compare/v1.1.0...v1.1.1) (2025-08-17)


### Bug Fixes

* simplify proxy header handling logic ([#15](https://github.com/sigbit/mcp-auth-proxy/issues/15)) ([cae3de3](https://github.com/sigbit/mcp-auth-proxy/commit/cae3de3e881230eb1c56f1241d0fa855444ac431))

## [1.1.0](https://github.com/sigbit/mcp-auth-proxy/compare/v1.0.0...v1.1.0) (2025-08-17)


### Features

* add PROXY_BEARER_TOKEN and PROXY_HEADERS options ([#13](https://github.com/sigbit/mcp-auth-proxy/issues/13)) ([abbbcf6](https://github.com/sigbit/mcp-auth-proxy/commit/abbbcf65a078335caae60b1ad00a5372ebedc3ab))

## [1.0.0](https://github.com/sigbit/mcp-auth-proxy/compare/v0.2.1...v1.0.0) (2025-08-17)


### ⚠ BREAKING CHANGES

* GLOBAL_SECRET environment variable and --global-secret flag are no longer supported. Secrets are now automatically generated and persisted.

### Features

* replace global secret parameter with auto-generated secret ([#6](https://github.com/sigbit/mcp-auth-proxy/issues/6)) ([05ccbb2](https://github.com/sigbit/mcp-auth-proxy/commit/05ccbb23f22b5a528faed558e6e242cda9f67849))


### Bug Fixes

* update release workflow permissions ([#8](https://github.com/sigbit/mcp-auth-proxy/issues/8)) ([2be8e5f](https://github.com/sigbit/mcp-auth-proxy/commit/2be8e5fccbe1cfcac69280b128f9ebecb2181d53))
