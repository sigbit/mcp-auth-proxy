FROM --platform=$BUILDPLATFORM golang:1.22-bookworm AS builder

ENV GOTOOLCHAIN=auto

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY ./ /app

ARG TARGETARCH
ARG TARGETOS
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-w -s" -o /app/bin/main .

FROM node:24-bookworm-slim AS node

# certificates only exists to provide the CA bundle for the scratch-based
# minimal image.
FROM debian:bookworm-slim AS certificates

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# minimal: just the proxy binary and CA certificates, for deployments that
# forward to an existing HTTP/SSE MCP server (no stdio subprocess support).
FROM scratch AS minimal

COPY --from=builder /app/bin/main /usr/local/bin/mcp-auth-proxy
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV DATA_PATH=/data

ENTRYPOINT [ "/usr/local/bin/mcp-auth-proxy" ]

# full: the default image, with Node.js and Python for running stdio MCP
# servers. Keep this as the last stage so a plain `docker build` produces it.
FROM debian:bookworm-slim AS full

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Node.js is needed to run npx-based MCP servers. Debian bookworm
# ships Node 18, which is end-of-life, so copy the runtime from the
# official Node 24 image instead of installing the distro packages.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && ln -s ../lib/node_modules/corepack/dist/corepack.js /usr/local/bin/corepack

COPY --from=builder /app/bin/main /usr/local/bin/mcp-auth-proxy
ENV DATA_PATH=/data

ENTRYPOINT [ "/usr/local/bin/mcp-auth-proxy" ]
