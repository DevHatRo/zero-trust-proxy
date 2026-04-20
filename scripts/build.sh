#!/bin/bash
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "dev")}
BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS="-w -s -X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME"


# Build server binary (custom Caddy with ztagents + ztrouter modules)
echo "Building server binaries (version=$VERSION, build_time=$BUILD_TIME)..."

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS" -o ./bin/zero-trust-proxy-server-linux-amd64 ./cmd/caddy
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$LDFLAGS" -o ./bin/zero-trust-proxy-server-linux-arm64 ./cmd/caddy

# Build agent binary
echo "Building agent binaries (version=$VERSION, build_time=$BUILD_TIME)..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS" -o ./bin/zero-trust-proxy-agent-linux-amd64 ./cmd/agent
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$LDFLAGS" -o ./bin/zero-trust-proxy-agent-linux-arm64 ./cmd/agent


# build certgen
echo "Building certgen binaries (version=$VERSION, build_time=$BUILD_TIME)..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS" -o ./bin/certgen-linux-amd64 ./cmd/certgen
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$LDFLAGS" -o ./bin/certgen-linux-arm64 ./cmd/certgen

chmod +x ./bin/zero-trust-proxy-* ./bin/certgen-*

echo "Build completed!"
