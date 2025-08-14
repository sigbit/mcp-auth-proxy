FROM docker.io/library/golang:alpine as builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY ./ /app
RUN go build -o bin/main .

FROM docker.io/library/alpine:latest

COPY --from=builder /app/bin/main /usr/local/bin/mcp-auth-proxy

ENTRYPOINT [ "/usr/local/bin/mcp-auth-proxy" ]
