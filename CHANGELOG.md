# Changelog

## [2.8.0](https://github.com/sigbit/mcp-auth-proxy/compare/v2.7.0...v2.8.0) (2026-04-03)


### Features

* forward authenticated user identity to upstream via headers ([#135](https://github.com/sigbit/mcp-auth-proxy/issues/135)) ([e847ed5](https://github.com/sigbit/mcp-auth-proxy/commit/e847ed5eec7b63110f1559b32356b67f5e3e1888)), closes [#130](https://github.com/sigbit/mcp-auth-proxy/issues/130)

## [2.7.0](https://github.com/sigbit/mcp-auth-proxy/compare/v2.6.1...v2.7.0) (2026-04-03)


### Features

* add unauthenticated /healthz endpoint for health checks ([#131](https://github.com/sigbit/mcp-auth-proxy/issues/131)) ([9803d0f](https://github.com/sigbit/mcp-auth-proxy/commit/9803d0fb3bc3e7c1bb915a01ce99495e02a27c53))


### Bug Fixes

* prevent panic on SSE reverse proxy when backend closes connection ([#128](https://github.com/sigbit/mcp-auth-proxy/issues/128)) ([76d1ac5](https://github.com/sigbit/mcp-auth-proxy/commit/76d1ac516899a763f75c8e015c3bfc08cb5a36b2))
* set JWT audience claim to external URL for RFC 8707 compliance ([#133](https://github.com/sigbit/mcp-auth-proxy/issues/133)) ([351305a](https://github.com/sigbit/mcp-auth-proxy/commit/351305a8bb6a34f3ce8f4b5444c7834c469e364c)), closes [#129](https://github.com/sigbit/mcp-auth-proxy/issues/129)

## [2.6.1](https://github.com/sigbit/mcp-auth-proxy/compare/v2.6.0...v2.6.1) (2026-03-18)


### Bug Fixes

* generate server-side OAuth state when client omits it ([#126](https://github.com/sigbit/mcp-auth-proxy/issues/126)) ([940e91e](https://github.com/sigbit/mcp-auth-proxy/commit/940e91e5979e3441cb590f2d706661bd7fdccf99))

## [2.6.0](https://github.com/sigbit/mcp-auth-proxy/compare/v2.5.4...v2.6.0) (2026-03-16)


### Features

* Add OIDC Attribute-Based Authorization ([#120](https://github.com/sigbit/mcp-auth-proxy/issues/120)) ([51b6e85](https://github.com/sigbit/mcp-auth-proxy/commit/51b6e85ff100a621e28720822908781b2561452d))
* support injecting cryptographic keys via env vars ([#119](https://github.com/sigbit/mcp-auth-proxy/issues/119)) ([ec9e857](https://github.com/sigbit/mcp-auth-proxy/commit/ec9e857c821e5b7cd1538f473427a366eefbc01f))


### Bug Fixes

* fix prettier formatting in oauth-setup.md ([#124](https://github.com/sigbit/mcp-auth-proxy/issues/124)) ([ef5731d](https://github.com/sigbit/mcp-auth-proxy/commit/ef5731dc8be1c2294b39f3eaabeb9f92df094689))
* normalize external URL with trailing slash per RFC 3986 ([#125](https://github.com/sigbit/mcp-auth-proxy/issues/125)) ([e377aa9](https://github.com/sigbit/mcp-auth-proxy/commit/e377aa9ed27b14a8f5d557512b1b9ad521e3fe35))

## [2.5.4](https://github.com/sigbit/mcp-auth-proxy/compare/v2.5.3...v2.5.4) (2026-03-03)


### Bug Fixes

* follow backend 307/308 redirects in transparent proxy ([#116](https://github.com/sigbit/mcp-auth-proxy/issues/116)) ([4546f40](https://github.com/sigbit/mcp-auth-proxy/commit/4546f407bba9e191bf6ffc08dac14d7baf8bbd9f))
* widen OAuth signature columns from VARCHAR(255) to VARCHAR(512) ([#117](https://github.com/sigbit/mcp-auth-proxy/issues/117)) ([68437b1](https://github.com/sigbit/mcp-auth-proxy/commit/68437b104fb7befd2671e92cf065ec40b3eba514)), closes [#111](https://github.com/sigbit/mcp-auth-proxy/issues/111)

## [2.5.3](https://github.com/sigbit/mcp-auth-proxy/compare/v2.5.2...v2.5.3) (2026-01-03)


### Bug Fixes

* send MCP initialize metadata for stdio backends ([#106](https://github.com/sigbit/mcp-auth-proxy/issues/106)) ([16de9cd](https://github.com/sigbit/mcp-auth-proxy/commit/16de9cd66e429fb27b0d8dbaacea99cdc9fd2730))

## [2.5.2](https://github.com/sigbit/mcp-auth-proxy/compare/v2.5.1...v2.5.2) (2025-12-04)


### Bug Fixes

* **docker:** update base image to golang:1.22-bookworm and switch to debian:bookworm-slim ([#98](https://github.com/sigbit/mcp-auth-proxy/issues/98)) ([dbeabda](https://github.com/sigbit/mcp-auth-proxy/commit/dbeabda6dfaa133e509ccacab6cb66ae10a44f2b))
* upgrade dependencies ([#100](https://github.com/sigbit/mcp-auth-proxy/issues/100)) ([8c1c8fd](https://github.com/sigbit/mcp-auth-proxy/commit/8c1c8fdc7dc36cc72087b7b06a8c1f2424607a2b))
* upgrade Go version to 1.25 in workflow files ([#101](https://github.com/sigbit/mcp-auth-proxy/issues/101)) ([3b869e9](https://github.com/sigbit/mcp-auth-proxy/commit/3b869e9136d2a67a8251b0e7b6fb611cc74241d9))

## [2.5.1](https://github.com/sigbit/mcp-auth-proxy/compare/v2.5.0...v2.5.1) (2025-12-04)


### Bug Fixes

* **idp:** replace hardcoded issuer with external URL in IDP router ([#96](https://github.com/sigbit/mcp-auth-proxy/issues/96)) ([a7dbccb](https://github.com/sigbit/mcp-auth-proxy/commit/a7dbccb687e4fb428320b0eae1111b902f749ffb))

## [2.5.0](https://github.com/sigbit/mcp-auth-proxy/compare/v2.4.0...v2.5.0) (2025-10-22)


### Features

* **tls:** add support for manual TLS certificate management and auto-reloading ([#90](https://github.com/sigbit/mcp-auth-proxy/issues/90)) ([f888826](https://github.com/sigbit/mcp-auth-proxy/commit/f888826c10c37b1eec698ce71a492fc2aadb96e9))

## [2.4.0](https://github.com/sigbit/mcp-auth-proxy/compare/v2.3.0...v2.4.0) (2025-10-22)


### Features

* **repository:** add SQL repository support with multiple backends ([#88](https://github.com/sigbit/mcp-auth-proxy/issues/88)) ([e3699bd](https://github.com/sigbit/mcp-auth-proxy/commit/e3699bdd93f190173b420b3851a2d3cf1c670742))

## [2.3.0](https://github.com/sigbit/mcp-auth-proxy/compare/v2.2.0...v2.3.0) (2025-08-28)


### Features

* **auth:** add no-provider-auto-select flag to disable auto-redirect ([#80](https://github.com/sigbit/mcp-auth-proxy/issues/80)) ([128e1cc](https://github.com/sigbit/mcp-auth-proxy/commit/128e1ccabd7d64d50241e4746df5cc539f7e8c55))

## [2.2.0](https://github.com/sigbit/mcp-auth-proxy/compare/v2.1.0...v2.2.0) (2025-08-25)


### Features

* support glob patterns for OIDC allowed users ([#77](https://github.com/sigbit/mcp-auth-proxy/issues/77)) ([fe65156](https://github.com/sigbit/mcp-auth-proxy/commit/fe65156fa691199db1fa4c22684a5bbb229986f3))


### Bug Fixes

* replace context.Done() with Wait() in backend tests ([#75](https://github.com/sigbit/mcp-auth-proxy/issues/75)) ([47ed79f](https://github.com/sigbit/mcp-auth-proxy/commit/47ed79f5ccdbc14d3872f2ea3279a36b9e0ac698))

## [2.1.0](https://github.com/sigbit/mcp-auth-proxy/compare/v2.0.0...v2.1.0) (2025-08-24)


### Features

* refactor backend architecture with interface pattern and trusted proxy support ([#72](https://github.com/sigbit/mcp-auth-proxy/issues/72)) ([9d7f9d0](https://github.com/sigbit/mcp-auth-proxy/commit/9d7f9d0ac237a89ba898cabbd4da371a7d4b2be1))

## [2.0.0](https://github.com/sigbit/mcp-auth-proxy/compare/v1.3.2...v2.0.0) (2025-08-24)


### ⚠ BREAKING CHANGES

* Authorization interface changed from separate GetUserID/Authorization calls to combined Authorization method

### Features

* enhance OAuth providers with organization and workspace support ([#69](https://github.com/sigbit/mcp-auth-proxy/issues/69)) ([239f2b2](https://github.com/sigbit/mcp-auth-proxy/commit/239f2b26d934c64860fcefc0faf784bdf1aa067d))


### Bug Fixes

* improve Docker image tagging strategy for releases ([#70](https://github.com/sigbit/mcp-auth-proxy/issues/70)) ([37bbe8c](https://github.com/sigbit/mcp-auth-proxy/commit/37bbe8c85ff504291ffec9280e8bd504ea154b42))

## [1.3.2](https://github.com/sigbit/mcp-auth-proxy/compare/v1.3.1...v1.3.2) (2025-08-21)


### Bug Fixes

* resolve configuration merge conflicts and update documentation ([#58](https://github.com/sigbit/mcp-auth-proxy/issues/58)) ([76791f8](https://github.com/sigbit/mcp-auth-proxy/commit/76791f88bcd5cc244144c704a914e8581b73a189))

## [1.3.1](https://github.com/sigbit/mcp-auth-proxy/compare/v1.3.0...v1.3.1) (2025-08-21)


### Miscellaneous Chores

* release 1.3.1 ([e5885f8](https://github.com/sigbit/mcp-auth-proxy/commit/e5885f82df8da5ee7b079cc6fc25d6390b4395ea))

## [1.3.0](https://github.com/sigbit/mcp-auth-proxy/compare/v1.2.3...v1.3.0) (2025-08-20)


### Features

* add OIDC provider support ([#40](https://github.com/sigbit/mcp-auth-proxy/issues/40)) ([f8edabe](https://github.com/sigbit/mcp-auth-proxy/commit/f8edabe7692efd1c187885bc60a54bcfd697399d))
* improve error handling with custom error template ([#47](https://github.com/sigbit/mcp-auth-proxy/issues/47)) ([2ff3804](https://github.com/sigbit/mcp-auth-proxy/commit/2ff380490b31a0ab492b1ded0ecf6e9f30f1c082))
* improve session security with HttpOnly and MaxAge options ([#46](https://github.com/sigbit/mcp-auth-proxy/issues/46)) ([9038812](https://github.com/sigbit/mcp-auth-proxy/commit/9038812eb3a0c48a1afb7473faeb9533571787a8))


### Bug Fixes

* improve authentication flow and session handling ([#45](https://github.com/sigbit/mcp-auth-proxy/issues/45)) ([cd28916](https://github.com/sigbit/mcp-auth-proxy/commit/cd28916bf00e76677a56df77fd0344372a39da81))
* remove oauth2.AccessTypeOffline from AuthCodeURL calls ([#41](https://github.com/sigbit/mcp-auth-proxy/issues/41)) ([a2d0d88](https://github.com/sigbit/mcp-auth-proxy/commit/a2d0d8831d0d06b0fa49cf79ab4a36526747ed45))

## [1.2.3](https://github.com/sigbit/mcp-auth-proxy/compare/v1.2.2...v1.2.3) (2025-08-19)


### Bug Fixes

* improve KVS repository error handling ([#36](https://github.com/sigbit/mcp-auth-proxy/issues/36)) ([126ff82](https://github.com/sigbit/mcp-auth-proxy/commit/126ff82ee22fc485ae19bcbdf076e7a35f34fd78))
* improve KVS update method error handling ([#37](https://github.com/sigbit/mcp-auth-proxy/issues/37)) ([92eb5d4](https://github.com/sigbit/mcp-auth-proxy/commit/92eb5d4fa25f89d6d3c7bb1e3ea375b0fa5d8709))

## [1.2.2](https://github.com/sigbit/mcp-auth-proxy/compare/v1.2.1...v1.2.2) (2025-08-18)


### Bug Fixes

* implement OAuth CSRF protection with state validation ([#30](https://github.com/sigbit/mcp-auth-proxy/issues/30)) ([e1030ba](https://github.com/sigbit/mcp-auth-proxy/commit/e1030ba0b1e6a704bab415c32633700b46608fba))

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
