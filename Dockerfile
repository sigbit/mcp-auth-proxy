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

FROM debian:bookworm-slim AS certificates

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

FROM scratch AS minimal

COPY --from=builder /app/bin/main /usr/local/bin/mcp-auth-proxy
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV DATA_PATH=/data

ENTRYPOINT [ "/usr/local/bin/mcp-auth-proxy" ]

FROM certificates AS full

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl python3 python3-pip nodejs npm \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/bin/main /usr/local/bin/mcp-auth-proxy
ENV DATA_PATH=/data

ENTRYPOINT [ "/usr/local/bin/mcp-auth-proxy" ]
