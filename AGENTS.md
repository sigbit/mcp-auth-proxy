# Repository Guidelines

## Project Structure & Module Organization

- `main.go`: CLI entry for the proxy.
- `pkg/mcp-proxy`: Server wiring (routing, TLS, startup/shutdown).
- `pkg/auth`: OAuth/OIDC/password providers and auth routes (`templates/`).
- `pkg/backend`: Stdio→HTTP bridge and transparent HTTP/S backends.
- `pkg/proxy`: Reverse proxy and header injection.
- `pkg/repository`: Lightweight KVS persistence.
- `pkg/utils`: Keys, randomness, logging helpers.
- `docs/`: Docusaurus site for product docs.

## Build, Test, and Development Commands

- Build: `go build -o bin/mcp-auth-proxy .` — compile the binary.
- Test: `go test ./...` — run unit tests.
- Coverage: `go test ./... -coverprofile=coverage.out && go tool cover -html=coverage.out -o coverage.html`.

## Coding Style & Naming Conventions

- Language: Go 1.22+ modules (`go.mod`).
- Formatting: `gofmt -s -w .` (CI checks formatting); `go fmt ./...` locally.
- Packages: lower-case names; exported identifiers use PascalCase; files `*_test.go` for tests.
- Imports: standard → third-party → local (`github.com/sigbit/mcp-auth-proxy/...`).

## Testing Guidelines

- Framework: Go `testing` package (`*_test.go`).
- Scope: Test auth providers, proxy behavior, and backend adapters in `pkg/...`.
- Naming: `TestXxx` with table-driven tests where useful.
- Run all: `go test ./...`; target a package: `go test ./pkg/proxy -v`.

## Commit & Pull Request Guidelines

- Commits: Conventional Commits (feat, fix, docs, refactor, perf, test, build, ci, chore, revert). Example: `feat: add GitHub OAuth provider support`.
- PRs: use `.github/pull_request_template.md` as the template; include a clear description, linked issues (`Fixes #123`), reproduction steps, and before/after notes. Include config snippets for new flags or env vars.
- CI: ensure `gofmt` passes and tests are green.

## Security & Configuration Tips

- Set `EXTERNAL_URL` correctly; accept TLS TOS with `--tls-accept-tos` when auto-TLS is detected.
- Avoid committing contents of `data/` (runtime-only).
