GOSEC_FLAGS = -quiet -exclude-dir=config -exclude-dir=logs

# CI gates at MEDIUM+ severity. Known-intentional findings are suppressed
# inline with `#nosec <rule> -- <justification>` at the offending line —
# G402 (agent→backend InsecureSkipVerify: backends are internal, the agent
# is the TLS termination point), G304 (operator-supplied config/CLI paths),
# G306 (certificate PEMs are public material), G710 (same-host HTTP→HTTPS
# redirect). No blanket rule exclusions.
GOSEC_CI_FLAGS = $(GOSEC_FLAGS) -severity=low

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

# CI gate: fails on MEDIUM+ findings not suppressed inline with #nosec.
sec:
	go run github.com/securego/gosec/v2/cmd/gosec@latest $(GOSEC_CI_FLAGS) ./...

# Full scan — all severities, no rule exclusions. Useful locally for cleanup.
sec-full:
	go run github.com/securego/gosec/v2/cmd/gosec@latest $(GOSEC_FLAGS) ./...
