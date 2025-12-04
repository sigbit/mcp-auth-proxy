FROM --platform=$BUILDPLATFORM golang:1.22-bookworm AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY ./ /app

ARG TARGETARCH
ARG TARGETOS
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-w -s" -o /app/bin/main .

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl python3 python3-pip nodejs npm \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/bin/main /usr/local/bin/mcp-auth-proxy
ENV DATA_PATH=/data

ENTRYPOINT [ "/usr/local/bin/mcp-auth-proxy" ]
