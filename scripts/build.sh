#!/bin/bash

# Build server binary
GOOS=linux GOARCH=amd64 go build -o ./bin/zero-trust-proxy-server-linux-amd64 ./cmd/server
GOOS=linux GOARCH=arm64 go build -o ./bin/zero-trust-proxy-server-linux-arm64 ./cmd/server

# Build agent binary
GOOS=linux GOARCH=amd64 go build -o ./bin/zero-trust-proxy-agent-linux-amd64 ./cmd/agent
GOOS=linux GOARCH=arm64 go build -o ./bin/zero-trust-proxy-agent-linux-arm64 ./cmd/agent


# build certgen
GOOS=linux GOARCH=amd64 go build -o ./bin/certgen-linux-amd64 ./cmd/certgen
GOOS=linux GOARCH=arm64 go build -o ./bin/certgen-linux-arm64 ./cmd/certgen
