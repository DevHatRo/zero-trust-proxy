GOSEC_FLAGS = -quiet -exclude-dir=config -exclude-dir=logs

# G402 (TLS InsecureSkipVerify) is intentional for agent→backend connections:
# backends sit on internal networks and often have self-signed / private-CA
# certs. The agent is the TLS termination point for the external edge.
GOSEC_CI_FLAGS = $(GOSEC_FLAGS) -severity=high -exclude=G402

.PHONY: build-server build-agent build-certgen build test sec sec-full

build-server:
	go build -o bin/zero-trust-proxy ./cmd/zero-trust-proxy

build-agent:
	go build -o bin/agent ./cmd/agent

build-certgen:
	go build -o bin/certgen ./cmd/certgen

build: build-server build-agent build-certgen

test:
	go test ./...

# CI gate: fails only on HIGH severity, excluding the known-intentional G402.
# New HIGH findings (other than G402) will break CI.
sec:
	go run github.com/securego/gosec/v2/cmd/gosec@latest $(GOSEC_CI_FLAGS) ./...

# Full scan — all severities, no rule exclusions. Useful locally for cleanup.
sec-full:
	go run github.com/securego/gosec/v2/cmd/gosec@latest $(GOSEC_FLAGS) ./...
