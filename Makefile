GOSEC_FLAGS = -quiet -exclude-dir=config -exclude-dir=logs

# G402 (TLS InsecureSkipVerify) is intentional for agent→backend connections:
# backends sit on internal networks and often have self-signed / private-CA
# certs. The agent is the TLS termination point for the external edge.
GOSEC_CI_FLAGS = $(GOSEC_FLAGS) -severity=high -exclude=G402

.PHONY: build-caddy build-agent build test sec sec-full

build-caddy:
	go build -o bin/caddy ./cmd/caddy

build-agent:
	go build -o bin/agent ./cmd/agent

build: build-caddy build-agent

test:
	go test ./...

# CI gate: fails only on HIGH severity, excluding the known-intentional G402.
# New HIGH findings (other than G402) will break CI.
sec:
	go run github.com/securego/gosec/v2/cmd/gosec@latest $(GOSEC_CI_FLAGS) ./...

# Full scan — all severities, no rule exclusions. Useful locally for cleanup.
sec-full:
	go run github.com/securego/gosec/v2/cmd/gosec@latest $(GOSEC_FLAGS) ./...
