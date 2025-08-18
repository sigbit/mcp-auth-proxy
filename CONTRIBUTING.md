# Contributing to MCP Auth Proxy

Thank you for your interest in contributing to MCP Auth Proxy! This document provides guidelines and information for developers.

## Commit Message Guidelines

This project follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification for commit messages. This helps with automated versioning, changelog generation, and makes the commit history more readable.

### Types

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation only changes
- **style**: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **perf**: A code change that improves performance
- **test**: Adding missing tests or correcting existing tests
- **build**: Changes that affect the build system or external dependencies
- **ci**: Changes to our CI configuration files and scripts
- **chore**: Other changes that don't modify src or test files
- **revert**: Reverts a previous commit

### Examples

```
feat: add GitHub OAuth provider support
fix: resolve token expiration handling
docs: update OAuth setup instructions
refactor: simplify authentication middleware
ci: add automated release workflow
```

### Breaking Changes

Breaking changes should be indicated by a `!` after the type/scope:

```
feat!: change authentication API to support multiple providers
```

## Pull Request Template

This project uses a pull request template to ensure consistency and completeness. Please follow the guidelines in [./.github/pull_request_template.md](./.github/pull_request_template.md) when creating pull requests.
